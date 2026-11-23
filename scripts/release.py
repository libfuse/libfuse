#!/usr/bin/env python3
"""Prepare, build and publish a libfuse release."""

import argparse
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every release this project has cut is tagged fuse-<major>.<minor>[.<patch>].
TAG_GLOB = 'fuse-[0-9]*'

# Tracked paths that must not end up in a release tarball.
TARBALL_EXCLUDES = ['.github', '.cirrus.yml']

# A release leaves a tree, a tarball, a signature and two text files behind.
# Only the tarball is gitignored, so none of it goes in the checkout.
OUTPUT_DIR = '/var/tmp/fuse-release'

REPO_URL = 'https://github.com/libfuse/libfuse'

# A passing run of this workflow says the tarball builds and tests clean.
RELEASE_WORKFLOW = 'release.yml'

PAGES_URL = 'git@github.com:libfuse/libfuse.github.io.git'

ANNOUNCE_TEMPLATE = """\
To: fuse-devel@lists.linux.dev
Subject: [ANNOUNCE] libfuse {version} has been released

Dear all,

I am pleased to announce the release of libfuse {version}.

The source code is available for download at
https://github.com/libfuse/libfuse/releases.

Please report any issues on this mailing list or the GitHub issue
tracker at https://github.com/libfuse/libfuse/issues.

From ChangeLog.rst:

{changes}

The following people have contributed code to this release:

{contributors}

(a full list of credits containing all known contributors is included in
the `AUTHORS` file).

Best,
-Bernd
"""


def fail(message):
    """Print a message and leave with a non-zero status."""
    print('release.py: ' + message, file=sys.stderr)
    sys.exit(1)


def stop(message):
    """Print why the release ended here and leave with a zero status."""
    print('stopped: ' + message)
    sys.exit(0)


def shown(argv, cwd=None):
    """Return a command as the shell would have to be given it."""
    text = shlex.join(argv)
    if cwd is not None:
        text += '   [in %s]' % cwd
    return text


def run(argv, cwd=None):
    """Run a command, showing it first, and fail the script when it fails."""
    # The echo goes to stderr.  Only the tarball path goes to stdout, so a
    # caller can read it with a command substitution.
    print('+ ' + shown(argv, cwd), file=sys.stderr)
    subprocess.run(argv, cwd=cwd or REPO_ROOT, check=True)


def output(argv, cwd=None):
    """Return a command's stdout without its trailing newline."""
    done = subprocess.run(argv, cwd=cwd or REPO_ROOT, check=True,
                          stdout=subprocess.PIPE, text=True)
    return done.stdout.rstrip('\n')


def succeeds(argv, cwd=None):
    """Return whether a command exits zero, with its output thrown away."""
    done = subprocess.run(argv, cwd=cwd or REPO_ROOT,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return done.returncode == 0


def require_tools(names):
    """Fail unless every external program a command runs is installed.

    All of them are named at once.  A release that stops on the second one
    after the first was installed costs another round.
    """
    missing = []
    for name in names:
        if shutil.which(name) is None:
            missing.append(name)
    if len(missing) > 0:
        fail('not installed: ' + ', '.join(missing))


def remove_path(path):
    """Delete a file or a directory, doing nothing when it is absent."""
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def confirm(question):
    """Ask a yes/no question and return the answer."""
    answer = input(question + ' [y/N] ').strip().lower()
    return answer == 'y' or answer == 'yes'


def step(dry_run, action, *lines):
    """Show what an action runs and return whether to carry it out.

    A dry run shows the same and answers no, so it changes nothing.
    """
    print('')
    print(action)
    for line in lines:
        print('    ' + line)
    if dry_run:
        return False
    return confirm('run it')


def required_step(dry_run, action, *lines):
    """Show an action the rest of the release needs; a no ends the release."""
    done = step(dry_run, action, *lines)
    if not done and not dry_run:
        stop(action.rstrip(':'))
    return done


def git(*args, cwd=None):
    """Return the stdout of a git command."""
    argv = ['git']
    for arg in args:
        argv.append(arg)
    return output(argv, cwd=cwd)


def worktree_is_clean(cwd=None):
    """Return whether a checkout has no modified tracked file."""
    return git('status', '--porcelain', '--untracked-files=no', cwd=cwd) == ''


def require_clean_worktree(root):
    """Fail unless a libfuse checkout has no modified tracked file."""
    if not worktree_is_clean(cwd=root):
        fail('%s has uncommitted changes' % root)


def tag_exists(tag):
    """Return whether the local repository has a tag."""
    return succeeds(['git', 'rev-parse', '-q', '--verify', 'refs/tags/' + tag])


def ls_remote_rows(remote, *patterns):
    """Return what a remote has each matching ref at, keyed by ref name."""
    # This asks the remote instead of fetching, so --dry-run changes
    # nothing.
    rows = {}
    for line in git('ls-remote', remote, *patterns).splitlines():
        commit, ref = line.split('\t')
        rows[ref] = commit
    return rows


def remote_tag_commit(remote, tag):
    """Return the commit a remote has a tag at, empty when it has none.

    The peeled pattern is not optional.  Without it an annotated tag reports
    its own object, which is never the commit it names.
    """
    ref = 'refs/tags/' + tag
    rows = ls_remote_rows(remote, ref, ref + '^{}')
    return rows.get(ref + '^{}') or rows.get(ref, '')


RELEASE_TAG = re.compile(r'^fuse-(\d+(?:\.\d+)*)$')


def version_key(version):
    """Return a version as a tuple of numbers, so versions can be ordered."""
    numbers = []
    for part in version.split('.'):
        numbers.append(int(part))
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers)


def previous_tag(version):
    """Return the newest release tag older than a version.

    Versions are compared here, not reachability.  Since 3.17 a release is
    cut on its own fuse-<major>.<minor>.x branch that never lands on master.
    """
    wanted = version_key(version)
    best_key = None
    best_tag = None
    for line in git('tag', '--list', TAG_GLOB).splitlines():
        match = RELEASE_TAG.match(line)
        if match is None:
            continue
        key = version_key(match.group(1))
        if key >= wanted:
            continue
        if best_key is None or key > best_key:
            best_key = key
            best_tag = line
    if best_tag is None:
        fail('no release tag is older than ' + version)
    return best_tag


VERSION_LINE = re.compile(r"^(\s*version:\s*')([^']+)(')")


def version_in(text):
    """Return the version a meson.build declares, e.g. X.Y.Z-rc0."""
    for line in text.splitlines():
        match = VERSION_LINE.match(line)
        if match is not None:
            return match.group(2)
    fail('meson.build has no version line')


def read_version(root):
    """Return the version a checkout declares."""
    return version_in((root / 'meson.build').read_text())


def file_at(commit, path):
    """Return a tracked file as of a commit."""
    return git('show', '%s:%s' % (commit, path))


def version_at(commit):
    """Return the version a commit declares."""
    return version_in(file_at(commit, 'meson.build'))


def write_version(root, version):
    """Replace the version a checkout's meson.build declares."""
    path = root / 'meson.build'
    lines = path.read_text().splitlines(keepends=True)
    for index in range(len(lines)):
        match = VERSION_LINE.match(lines[index])
        if match is None:
            continue
        lines[index] = match.group(1) + version + lines[index][match.end(2):]
        path.write_text(''.join(lines))
        return
    fail('meson.build has no version line')


UNRELEASED_HEADING = 'Unreleased Changes'

# A release branch heads its open section with the version it is going to be
# instead, e.g. "libfuse 3.18.3-rc1 (unreleased)".
UNRELEASED_VERSION_HEADING = re.compile(r'^libfuse\s+\S+\s+\(unreleased\)$',
                                        re.IGNORECASE)


def is_rst_underline(line):
    """Return whether a line is the '=' rule below a heading."""
    return line != '' and line == '=' * len(line)


def is_unreleased_heading(line):
    """Return whether a heading names the section this release closes."""
    if line == UNRELEASED_HEADING:
        return True
    return UNRELEASED_VERSION_HEADING.match(line) is not None


def find_unreleased_heading(root):
    """Return the line index and text of the open section, -1 when it has none.

    Whether a closed section is the release being cut or a ChangeLog.rst
    nobody opened is the caller's to tell apart.
    """
    lines = (root / 'ChangeLog.rst').read_text().splitlines()
    for index in range(len(lines) - 1):
        if is_unreleased_heading(lines[index]) and is_rst_underline(lines[index + 1]):
            return index, lines[index]
    return -1, ''


def changelog_heading(version, today):
    """Return the ChangeLog.rst heading of one release."""
    return 'libfuse %s (%s)' % (version, today)


def close_changelog(root, index, version, today):
    """Rename the heading of the open section to the one of this release."""
    path = root / 'ChangeLog.rst'
    lines = path.read_text().splitlines()
    heading = changelog_heading(version, today)
    lines[index] = heading
    lines[index + 1] = '=' * len(heading)
    path.write_text('\n'.join(lines) + '\n')


def changelog_section(version, changelog):
    """Return one release's ChangeLog.rst entries, its heading excluded."""
    lines = changelog.splitlines()
    heading = 'libfuse %s (' % version
    start = None
    for index in range(len(lines) - 1):
        if lines[index].startswith(heading) and is_rst_underline(lines[index + 1]):
            start = index + 2
            break
    if start is None:
        fail('ChangeLog.rst has no section for ' + version)
    end = len(lines)
    for index in range(start, len(lines) - 1):
        if lines[index] != '' and is_rst_underline(lines[index + 1]):
            end = index
            break
    return '\n'.join(lines[start:end]).strip('\n')


MAIL_IN_ANGLES = re.compile(r'<([^>]+)>')


def known_author_mails(root):
    """Return the lower-cased mail addresses AUTHORS already lists."""
    known = set()
    for match in MAIL_IN_ANGLES.finditer((root / 'AUTHORS').read_text()):
        known.add(match.group(1).lower())
    return known


def new_authors(root, branch, prev_tag):
    """Return every author since a tag that AUTHORS does not list yet."""
    known = known_author_mails(root)
    added = []
    listing = git('log', '--format=%aN <%aE>', prev_tag + '..' + branch)
    for line in listing.splitlines():
        match = MAIL_IN_ANGLES.search(line)
        if match is None:
            continue
        mail = match.group(1).lower()
        if mail in known:
            continue
        known.add(mail)
        added.append(line)
    return added


def extend_authors(root, prev_tag, added):
    """Append authors to AUTHORS, under a heading naming the previous tag."""
    path = root / 'AUTHORS'
    text = path.read_text()
    if not text.endswith('\n'):
        text += '\n'
    text += '\n# New authors since %s\n' % prev_tag
    for line in added:
        text += line + '\n'
    path.write_text(text)


def signify_key_name(tag):
    """Return the signing key basename of a tag: fuse-X.Y for fuse-X.Y.Z."""
    return tag.rsplit('.', 1)[0]


def next_version_question(key_name):
    """Return what prepare asks before it generates a signing key."""
    return 'Is %s going to be the next version?' % key_name


def missing_signing_key(root, version, force_new_version):
    """Return the next minor's key basename, empty when the release has it.

    A release is signed with the key of its own minor, so only a .0 has a
    successor whose key does not exist yet.  A series whose .0 never went
    out leaves that key to the first patch release that does, which is what
    force_new_version says.
    """
    major, minor, patch = version.split('.')
    if patch != '0' and not force_new_version:
        return ''
    name = 'fuse-%s.%d' % (major, int(minor) + 1)
    if (root / 'signify' / (name + '.pub')).exists():
        return ''
    return name


def signing_key_commands(root, name):
    """Return the commands that put a signing key in a release checkout.

    The pair is generated where the script runs.  That signify/ keeps the
    .sec every release of the minor signs with, and a release checkout of
    another branch is thrown away after the release.
    """
    public = REPO_ROOT / 'signify' / (name + '.pub')
    secret = REPO_ROOT / 'signify' / (name + '.sec')
    commands = []
    if not public.exists():
        commands.append(['signify-openbsd', '-G', '-n',
                         '-p', str(public), '-s', str(secret)])
    if root != REPO_ROOT:
        commands.append(['cp', str(public), str(root / 'signify')])
    commands.append(['git', '-C', str(root), 'add',
                     str(root / 'signify' / (name + '.pub'))])
    return commands


def create_signing_key(root, name):
    """Put a signing key in a release checkout and stage its public half."""
    for argv in signing_key_commands(root, name):
        run(argv)
    print('signify: %s.sec is gitignored, back it up' % name)


def tarball_commands(tarball_name, output_dir, commit):
    """Return the commands that pack one commit, by what each one does."""
    return {
        'archive': ['git', 'archive', '--format=tar',
                    '--prefix=' + tarball_name + '/', commit],
        'extract': ['tar', '-x', '-C', str(output_dir)],
        'doxygen': ['doxygen', 'doc/Doxyfile'],
        'pack': ['tar', '-czf', str(output_dir / (tarball_name + '.tar.gz')),
                 '-C', str(output_dir), tarball_name],
    }


def tarball_plan(tarball_name, output_dir, commit):
    """Return what packing a commit does, as the shell would be given it.

    The name is passed in.  publish reports the plan before the tag it packs
    exists, so the name cannot be read out of the commit here.
    """
    work = output_dir / tarball_name
    commands = tarball_commands(tarball_name, output_dir, commit)
    excluded = []
    for name in TARBALL_EXCLUDES:
        excluded.append(str(work / name))
    return [shown(commands['archive']) + ' | ' + shown(commands['extract']),
            'find %s -name .gitignore -delete' % work,
            'rm -r ' + ' '.join(excluded),
            shown(commands['doxygen'], work),
            shown(commands['pack'])]


def build_tarball(commit, output_dir):
    """Extract a commit, build the API documentation into it, and pack it up."""
    # The name comes from the packed tree.  A tarball cannot claim a version
    # its own meson.build does not.
    tarball_name = 'fuse-' + version_at(commit)
    commands = tarball_commands(tarball_name, output_dir, commit)
    output_dir.mkdir(parents=True, exist_ok=True)
    work = output_dir / tarball_name
    remove_path(work)

    print('+ %s | %s' % (shown(commands['archive']), shown(commands['extract'])),
          file=sys.stderr)
    archive = subprocess.Popen(commands['archive'], cwd=REPO_ROOT,
                               stdout=subprocess.PIPE)
    extract = subprocess.Popen(commands['extract'], stdin=archive.stdout)
    archive.stdout.close()
    extract.wait()
    if archive.wait() != 0 or extract.returncode != 0:
        fail('could not extract ' + commit)

    for path in work.rglob('.gitignore'):
        path.unlink()
    for name in TARBALL_EXCLUDES:
        remove_path(work / name)

    # Doxyfile reads INPUT = . and writes to OUTPUT_DIRECTORY = doc.  That
    # puts the html where the tarball ships it.
    run(commands['doxygen'], cwd=work)
    run(commands['pack'])
    return output_dir / (tarball_name + '.tar.gz')


def checkout_test_commands(root, build_dir):
    """Return the commands that build a checkout with warnings fatal.

    meson.build asks for warning_level=2 and nothing more, so -Dwerror=true
    is what makes a warning end the release instead of the release tarball.
    """
    return [['meson', 'setup', '-Dwerror=true', str(build_dir), str(root)],
            ['ninja', '-C', str(build_dir)]]


def checkout_test_plan(root, build_dir):
    """Return what building a checkout does, as shell commands."""
    lines = ['rm -rf ' + str(build_dir)]
    for argv in checkout_test_commands(root, build_dir):
        lines.append(shown(argv))
    return lines


def test_checkout(root, build_dir):
    """Build a checkout, and fail the release when it does not build."""
    remove_path(build_dir)
    build_dir.parent.mkdir(parents=True, exist_ok=True)
    for argv in checkout_test_commands(root, build_dir):
        run(argv)


def ci_build_argv(work_dir):
    """Return the command that builds and tests an unpacked tarball."""
    argv = ['test/ci-build.sh', '--name', 'release']
    if work_dir is not None:
        argv += ['--work-dir', str(work_dir)]
    return argv


def tarball_test_plan(tarball, verify_dir, work_dir):
    """Return what testing a packed tarball does, as shell commands."""
    unpacked = verify_dir / tarball.name.removesuffix('.tar.gz')
    return ['rm -rf ' + str(verify_dir),
            shown(['tar', '-xzf', str(tarball), '-C', str(verify_dir)]),
            shown(ci_build_argv(work_dir), unpacked)]


def test_tarball(tarball, verify_dir, work_dir):
    """Build and test what a tarball ships, and fail the script when it fails.

    The tarball is unpacked somewhere else than it was packed from.  The
    build then sees what a downloader gets, not what git archive left behind.
    """
    unpacked = verify_dir / tarball.name.removesuffix('.tar.gz')
    remove_path(verify_dir)
    verify_dir.mkdir(parents=True)
    run(['tar', '-xzf', str(tarball), '-C', str(verify_dir)])
    run(ci_build_argv(work_dir), cwd=unpacked)


def key_path(tag, suffix):
    """Return one half of the key that signs a tag: .sec signs, .pub verifies."""
    return REPO_ROOT / 'signify' / (signify_key_name(tag) + suffix)


def signing_key(tag):
    """Return the secret key that signs a tag, failing when it is absent."""
    secret = key_path(tag, '.sec')
    if not secret.exists():
        fail('missing signing key ' + str(secret))
    return secret


def contributors(prev_tag, tag):
    """Return everyone's sorted "Name <mail>" between two tags."""
    listing = git('log', '--pretty=%an <%aE>', prev_tag + '..' + tag)
    people = set()
    for line in listing.splitlines():
        if line != '':
            people.add(line)
    sorted_people = list(people)
    sorted_people.sort()
    return sorted_people


def contributor_block(prev_tag, tag):
    """Return the contributors between two tags, one per line."""
    text = ''
    for line in contributors(prev_tag, tag):
        text += line + '\n'
    return text.rstrip('\n')


def release_notes(version, prev_tag, tag, changelog):
    """Return the GitHub release body of a release."""
    text = changelog_section(version, changelog)
    text += '\n\nThe following people have contributed code to this release:\n\n'
    text += contributor_block(prev_tag, tag) + '\n'
    return text


def announce_mail(version, prev_tag, tag, changelog):
    """Return the fuse-devel announcement, ready to be sent by hand."""
    return ANNOUNCE_TEMPLATE.format(
        version=version,
        changes=changelog_section(version, changelog),
        contributors=contributor_block(prev_tag, tag))


def docs_commit_message(tag):
    """Return the commit message of an API documentation update."""
    return 'Re-generated doxygen documentation for ' + tag


def docs_plan(tag, work, pages_dir):
    """Return what publishing the API documentation does, as shell commands."""
    doxygen_dir = pages_dir / 'doxygen'
    lines = []
    if not pages_dir.exists():
        lines.append(shown(['git', 'clone', PAGES_URL, str(pages_dir)]))
    lines.append('rm -r ' + str(doxygen_dir))
    lines.append('cp -r %s %s' % (work / 'doc' / 'html', doxygen_dir))
    lines.append(shown(['git', 'add', '-A', 'doxygen'], pages_dir))
    lines.append(shown(['git', 'commit', '-m', docs_commit_message(tag)],
                       pages_dir))
    lines.append(shown(['git', 'push'], pages_dir))
    return lines


def update_api_docs(tag, work, pages_dir):
    """Replace the pages repository's doxygen/ tree with this release's."""
    if not pages_dir.exists():
        run(['git', 'clone', PAGES_URL, str(pages_dir)])
    if not worktree_is_clean(cwd=pages_dir):
        fail('%s has uncommitted changes' % pages_dir)

    doxygen_dir = pages_dir / 'doxygen'
    remove_path(doxygen_dir)
    shutil.copytree(work / 'doc' / 'html', doxygen_dir)
    run(['git', 'add', '-A', 'doxygen'], cwd=pages_dir)
    if git('status', '--porcelain', 'doxygen', cwd=pages_dir) == '':
        print('API documentation unchanged')
        return False
    run(['git', 'commit', '-m', docs_commit_message(tag)], cwd=pages_dir)
    return True


def release_branch(wanted):
    """Return the branch to release and the commit it points at.

    Any checkout releases any branch.  What it has to carry is the signing
    key of the release, which signing_key() reads and reports on its own.
    """
    branch = wanted
    if branch is None:
        branch = git('rev-parse', '--abbrev-ref', 'HEAD')
        if branch == 'HEAD':
            fail('HEAD is detached; check out the branch to release, or name'
                 ' it with --branch')
    if not succeeds(['git', 'rev-parse', '-q', '--verify',
                     'refs/heads/' + branch]):
        fail('no such branch: ' + branch)
    return branch, git('rev-parse', 'refs/heads/' + branch)


def remote_branch_commit(remote, branch):
    """Return the commit a remote has a branch at, empty when it has none."""
    ref = 'refs/heads/' + branch
    return ls_remote_rows(remote, ref).get(ref, '')


def require_pushed(remote, branch, commit):
    """Fail unless a remote carries a branch, at the commit being released."""
    remote_commit = remote_branch_commit(remote, branch)
    if remote_commit == '':
        fail('%s has no branch %s; push the release commit first'
             % (remote, branch))
    if remote_commit != commit:
        fail('%s/%s does not point at %s; push the release commit first'
             % (remote, branch, commit[:12]))


def branch_update_commands(remote, branch, checked_out):
    """Return the command that fast-forwards a branch to its remote.

    Both refuse anything but a fast-forward, so a diverged branch is safe.
    A branch that is checked out cannot be fetched into.
    """
    if checked_out:
        return ['git', 'pull', '--ff-only', remote, branch]
    return ['git', 'fetch', remote, '%s:%s' % (branch, branch)]


def publish_command(branch):
    """Return the publish that releases what prepare left on a branch."""
    argv = [sys.argv[0], 'publish']
    if branch is not None:
        argv.extend(['--branch', branch])
    return shown(argv)


def compare_url(base, branch):
    """Return the URL of the page that opens a pull request for a branch."""
    return '%s/compare/%s...%s?expand=1' % (REPO_URL, base, branch)


def require_workflow_passed(dry_run, branch, commit):
    """Ask for the release workflow, and end the release unless it passed."""
    print('')
    print('Run %s on %s and wait for it to pass:' % (RELEASE_WORKFLOW, branch))
    print('    %s/actions/workflows/%s' % (REPO_URL, RELEASE_WORKFLOW))
    print('    Run workflow -> Branch: %s' % branch)
    if dry_run:
        return
    print('')
    if not confirm('Did that run of %s pass?' % commit[:12]):
        stop('the release workflow has not passed')


def add_worktree(branch):
    """Check a branch out on its own, and return where.

    A release branch need not carry release.py at all, so checking it out in
    the checkout the script runs from would take the script away mid-release.
    """
    root = Path(tempfile.mkdtemp(prefix='fuse-release-')) / 'checkout'
    run(['git', 'worktree', 'add', str(root), branch])
    return root


def remove_worktree(root):
    """Take a checkout added for one release back out.

    Whatever is left in it is thrown away.  A release that ended early wrote
    only into this checkout, and a failure here would hide why it ended.
    """
    run(['git', 'worktree', 'remove', '--force', str(root)])
    remove_path(root.parent)


def prepare_checkout(args):
    """Return the checkout to prepare a release in and the branch it has out.

    Without --branch that is the checkout the script runs in.  With it the
    branch is brought up to what the remote has it at first, so the release
    is cut on the commit everyone else can see.
    """
    if args.branch is None:
        return REPO_ROOT, git('rev-parse', '--abbrev-ref', 'HEAD')
    if not succeeds(['git', 'rev-parse', '-q', '--verify',
                     'refs/heads/' + args.branch]):
        fail('no such branch: ' + args.branch)
    remote_commit = remote_branch_commit(args.remote, args.branch)
    if remote_commit != '' and remote_commit != git('rev-parse', 'refs/heads/'
                                                    + args.branch):
        update_argv = branch_update_commands(args.remote, args.branch, False)
        if required_step(args.dry_run,
                         'Update %s from %s:' % (args.branch, args.remote),
                         shown(update_argv)):
            run(update_argv)
    return add_worktree(args.branch), args.branch


def cmd_prepare(args):
    """Make the "Released ..." commit, in the checkout that release needs."""
    root, branch = prepare_checkout(args)
    try:
        prepare_commit(args, root, branch)
    finally:
        if root != REPO_ROOT:
            remove_worktree(root)


def prepare_commit(args, root, branch):
    """Write what a release changes in one checkout, and commit it there."""
    require_clean_worktree(root)
    version = args.version
    if re.fullmatch(r'\d+\.\d+\.\d+', version) is None:
        fail('version must be MAJOR.MINOR.PATCH, got ' + version)
    tag = 'fuse-' + version
    if tag_exists(tag):
        fail(tag + ' exists already')
    prev_tag = previous_tag(version)

    # Everything that can refuse the release runs before the first edit.  A
    # refused one leaves no half-prepared tree behind.
    old_version = read_version(root)
    unreleased_index, unreleased_heading = find_unreleased_heading(root)
    # A branch that carries the release has the section closed and declares
    # the version.  One re-opened for another backport declares it too, and
    # is prepared again.
    if unreleased_index < 0:
        if old_version == version:
            fail('%s carries %s already; publish it with\n    %s'
                 % (branch, version, publish_command(args.branch)))
        fail('ChangeLog.rst has neither a "%s" section nor an unreleased'
             ' version heading' % UNRELEASED_HEADING)
    key_name = missing_signing_key(root, version, args.force_new_version)
    tools = []
    if not args.skip_test:
        tools.extend(['meson', 'ninja'])
    if key_name != '':
        tools.append('signify-openbsd')
    require_tools(tools)
    added = new_authors(root, branch, prev_tag)
    today = date.today().isoformat()
    commit_argv = ['git', '-C', str(root), 'commit', '-s', '--all',
                   '-m', 'Released ' + tag]

    print("meson.build:   version: '%s' -> version: '%s'"
          % (old_version, version))
    print('ChangeLog.rst: %s -> %s'
          % (unreleased_heading, changelog_heading(version, today)))
    if len(added) == 0:
        print('AUTHORS:       no new authors since ' + prev_tag)
    for line in added:
        print('AUTHORS:       + ' + line)
    if key_name != '':
        print('signify:       ' + next_version_question(key_name))
        for argv in signing_key_commands(root, key_name):
            print('+ ' + shown(argv))
    print('+ ' + shown(commit_argv))

    # A key of the wrong name is one the next release is stuck with, so the
    # name is agreed to before anything is written.
    if key_name != '' and not args.dry_run:
        if not confirm(next_version_question(key_name)):
            stop('the next version is not ' + key_name)

    # The last refusal, and the slow one, so every question is answered
    # before it starts.  A branch that does not build gets no release commit.
    build_dir = Path(OUTPUT_DIR) / 'prepare-build'
    if not args.skip_test:
        if required_step(args.dry_run, 'Build %s, warnings fatal:' % branch,
                         *checkout_test_plan(root, build_dir)):
            test_checkout(root, build_dir)

    if not args.dry_run:
        write_version(root, version)
        close_changelog(root, unreleased_index, version, today)
        if len(added) > 0:
            extend_authors(root, prev_tag, added)
        if key_name != '':
            create_signing_key(root, key_name)
        run(commit_argv)

    push_argv = ['git', 'push', args.remote, branch]
    if step(args.dry_run, 'Push the release branch:', shown(push_argv)):
        run(push_argv)

    print('')
    print('Prepared %s on top of %s.' % (tag, prev_tag))
    if args.branch is None:
        print('Open the pull request:')
        print('    ' + compare_url(args.base, branch))
        print('Once it is merged:')
        print('    git checkout ' + args.base)
        print('    ' + publish_command(args.branch))
    else:
        print('Once it is pushed:')
        print('    ' + publish_command(args.branch))
    if args.dry_run:
        print('')
        print('nothing was changed')


def cmd_tarball(args):
    """Build the release tarball of a commit and print its path."""
    require_tools(['doxygen'])
    if not succeeds(['git', 'rev-parse', '-q', '--verify',
                     args.commit + '^{commit}']):
        fail('no such commit: ' + args.commit)
    output_dir = Path(args.output_dir).resolve()
    if args.dry_run:
        tarball_name = 'fuse-' + version_at(args.commit)
        for line in tarball_plan(tarball_name, output_dir, args.commit):
            print('+ ' + line)
        print('nothing was changed')
        return
    print(str(build_tarball(args.commit, output_dir)))


def cmd_test(args):
    """Build and test what a release tarball ships."""
    tarball = Path(args.tarball).resolve()
    if not tarball.is_file():
        fail('no such tarball: ' + str(tarball))
    if not tarball.name.endswith('.tar.gz'):
        fail('not a release tarball: ' + str(tarball))
    verify_dir = tarball.parent / 'verify'
    if args.dry_run:
        for line in tarball_test_plan(tarball, verify_dir, args.work_dir):
            print('+ ' + line)
        print('nothing was changed')
        return
    test_tarball(tarball, verify_dir, args.work_dir)


def cmd_publish(args):
    """Tag, build and sign the release a branch carries."""
    dry_run = args.dry_run
    # Before the first question, so an uninstalled program is not found
    # halfway through a release.
    require_tools(['doxygen', 'signify-openbsd'])
    branch, commit = release_branch(args.branch)

    # The merged release commit arrives on the remote first.  Everything below
    # is derived from the commit, so the branch is caught up before that.
    remote_commit = remote_branch_commit(args.remote, branch)
    if remote_commit != '' and remote_commit != commit:
        update_argv = branch_update_commands(
            args.remote, branch,
            branch == git('rev-parse', '--abbrev-ref', 'HEAD'))
        if required_step(dry_run, 'Update %s from %s:' % (branch, args.remote),
                         shown(update_argv)):
            run(update_argv)
            commit = git('rev-parse', 'refs/heads/' + branch)
        else:
            # Only a dry run reaches this.  The release commit is not here yet,
            # so there is nothing further to report.
            print('')
            print('nothing was changed')
            return

    # This reads the commit, not the checkout.  Publishing a branch that is
    # not checked out then releases what that branch says.
    version = version_at(commit)
    if '-' in version:
        fail('meson.build declares %s; only a final version is released'
             % version)
    tag = 'fuse-' + version
    output_dir = Path(args.output_dir).resolve()
    work = output_dir / tag
    tarball = output_dir / (tag + '.tar.gz')
    pages_dir = Path(args.pages_dir).resolve()

    # Everything that can refuse the release runs before the tag.  A refused
    # one leaves nothing behind, and --dry-run reports the same refusals.
    prev_tag = previous_tag(version)
    changelog = file_at(commit, 'ChangeLog.rst')
    changelog_section(version, changelog)
    secret = signing_key(tag)
    require_pushed(args.remote, branch, commit)
    # A tag the remote carries is the release everyone else can see.  One at
    # another commit is a different release under this name.
    published_commit = remote_tag_commit(args.remote, tag)
    if published_commit != '' and published_commit != commit:
        fail('%s carries %s at %s, not at %s'
             % (args.remote, tag, published_commit[:12], commit[:12]))
    tag_is_public = published_commit == commit
    print('%s (%s..%s) at %s on %s'
          % (tag, prev_tag, tag, commit[:12], branch))

    # The tarball is packed and tested before the tag.  A broken tarball can
    # be thrown away, a pushed tag cannot.
    # Both paths carry the version, so an earlier commit of it leaves them
    # exactly here.  Packing again is what keeps the tarball, the API
    # documentation and the tag on one commit.
    if required_step(dry_run, 'Pack the tarball:',
                     *tarball_plan(tag, output_dir, commit)):
        tarball = build_tarball(commit, output_dir)

    verify_dir = output_dir / 'verify'
    if not args.skip_test:
        if required_step(dry_run, 'Test the tarball:',
                         *tarball_test_plan(tarball, verify_dir,
                                            args.work_dir)):
            test_tarball(tarball, verify_dir, args.work_dir)

    # This comes after the local test.  A tarball that fails there never
    # reaches GitHub.  A public tag was let out by a run that passed.
    if not tag_is_public and not args.skip_workflow:
        require_workflow_passed(dry_run, branch, commit)

    tag_argv = ['git', 'tag', '-s', '-m', tag, tag, commit]
    if tag_exists(tag):
        if git('rev-parse', tag + '^{commit}') != commit:
            fail('%s does not point at %s' % (tag, branch))
        print('tag %s exists already' % tag)
    elif required_step(dry_run, 'Tag the release commit:', shown(tag_argv)):
        run(tag_argv)

    signature = Path(str(tarball) + '.sig')
    sign_argv = ['signify-openbsd', '-S', '-s', str(secret), '-m', str(tarball)]
    verify_argv = ['signify-openbsd', '-V', '-p', str(key_path(tag, '.pub')),
                   '-m', str(tarball)]
    if required_step(dry_run, 'Sign the tarball:', 'rm -f ' + str(signature),
                     shown(sign_argv), shown(verify_argv)):
        remove_path(signature)
        run(sign_argv)
        run(verify_argv)

    notes_file = output_dir / (tag + '-notes.md')
    announce_file = output_dir / (tag + '-announce.txt')
    if required_step(dry_run, 'Write the release notes and the announcement:',
                     'write ' + str(notes_file),
                     'write ' + str(announce_file)):
        notes_file.write_text(release_notes(version, prev_tag, tag, changelog))
        announce_file.write_text(announce_mail(version, prev_tag, tag,
                                               changelog))

    # From here on a no skips one publication and keeps the rest.  What is
    # left does not depend on it, and the instructions below are needed
    # either way.
    push_argv = ['git', 'push', args.remote, 'refs/tags/' + tag]
    if tag_is_public:
        print('%s carries %s already' % (args.remote, tag))
    elif step(dry_run, 'Push the tag:', shown(push_argv)):
        run(push_argv)

    if not args.skip_docs:
        if step(dry_run, 'Publish the API documentation:',
                *docs_plan(tag, work, pages_dir)):
            if update_api_docs(tag, work, pages_dir):
                run(['git', 'push'], cwd=pages_dir)

    # These two come last and together.  Everything above is done, these
    # are not.
    print('')
    print('Create the release at %s/releases/new?tag=%s' % (REPO_URL, tag))
    print('    title:  %s' % tag)
    print('    body:   %s' % notes_file)
    print('    attach: %s' % tarball)
    print('            %s' % signature)
    print('')
    print('Send the announcement: ' + str(announce_file))
    if dry_run:
        print('')
        print('nothing was changed')


STEPS = """\
Step 1  release.py prepare X.Y.Z  commit the version, ChangeLog, AUTHORS
                                  and the key of the next release
Step 2                            get that pull request merged
Step 3  release.py publish        pack, test, tag, sign and push it
Step 4                            create the GitHub release
Step 5                            send the announcement mail

Steps 2, 4 and 5 are done by hand; publish prints what they need.  tarball
and test pack and check one commit on their own; publish and the release
workflow run both.  Every command that changes something takes --dry-run.
Details: dev-docs/release-process.md
"""

PREPARE_HELP = """\
Set the version in meson.build, close the open section of ChangeLog.rst,
whether it is headed Unreleased Changes or "libfuse <version>
(unreleased)", add the new authors to AUTHORS, generate the signing key
the next release needs, and commit all of it as "Released fuse-<version>".
Run this on the branch whose pull request carries the release.

The branch is built with -Dwerror=true before the first of those is
written, so a branch that does not build gets no release commit.
--skip-test leaves that out.

The push of that branch is offered and can be skipped.  Opening the pull
request and merging it are done by hand, and the URL is printed.

--branch commits the release to another branch instead, which is brought
up to the remote and checked out on its own.  A maintenance release is
cut that way: the branch keeps neither release.py nor a pull request, and
master stays checked out.

A .0 release generates the next minor's signing key, and asks first
whether that is going to be the next version.  --force-new-version
generates it in a patch release too, for a series whose .0 never went
out.
"""

TARBALL_HELP = """\
Extract a commit with git archive, build the API documentation into the
extracted tree, pack it, and print the path of the tarball.  It is named
after the version the packed meson.build declares.
"""

TEST_HELP = """\
Unpack a release tarball next to itself and run test/ci-build.sh in the
unpacked tree.  The build then sees what a downloader gets, not the
checkout it was packed from.  A file git archive leaves out fails here.
"""

PUBLISH_HELP = """\
Pack the tarball, test it, ask for a passing run of the release workflow,
create the signed tag, sign the tarball, write the release notes and the
announcement mail, push the tag and the API documentation, and print what
GitHub and the mail still need by hand.  Every action is shown with the
command it runs and confirmed on its own; a no before the tag ends the
release with nothing to take back.

The version and the ChangeLog are read out of the branch that is
released, --branch or the checked-out one.  That branch has to point at
the same commit as its counterpart on the remote, and a fast-forward to
it is offered when it does not.  The signing key is read from the
checkout, which is why a release branch is released from master or a
branch of it rather than from itself.
"""


def main():
    parser = argparse.ArgumentParser(
        description=__doc__ + '\n\n' + STEPS,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)

    # Every command that changes something can report instead, so this is
    # shared.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--dry-run', action='store_true',
                        help='report what would be done and change nothing')

    prepare = commands.add_parser(
        'prepare', parents=[common], description=PREPARE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help='make the "Released ..." commit')
    prepare.add_argument('version', help='release version, X.Y.Z')
    prepare.add_argument('--branch',
                         help='branch to commit the release to, checked out on'
                              ' its own (default: the checked-out branch)')
    prepare.add_argument('--remote', default='origin',
                         help='remote to push the branch to (default: origin)')
    prepare.add_argument('--base', default='master',
                         help='branch the pull request merges into'
                              ' (default: master)')
    prepare.add_argument('--skip-test', action='store_true',
                         help='do not build the branch before committing the'
                              ' release')
    prepare.add_argument('--force-new-version', action='store_true',
                         help='generate the next minor\'s signing key in a'
                              ' patch release, for a series whose .0 was'
                              ' never released')
    prepare.set_defaults(func=cmd_prepare)

    tarball = commands.add_parser(
        'tarball', parents=[common], description=TARBALL_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help='build the release tarball')
    tarball.add_argument('commit', help='what to pack, e.g. fuse-X.Y.Z or HEAD')
    tarball.add_argument('--output-dir', default=OUTPUT_DIR,
                         help='where to extract and pack (default: %(default)s)')
    tarball.set_defaults(func=cmd_tarball)

    test = commands.add_parser(
        'test', parents=[common], description=TEST_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help='build and test what a tarball ships')
    test.add_argument('tarball', help='what to test, e.g. fuse-X.Y.Z.tar.gz')
    test.add_argument('--work-dir',
                      help='where test/ci-build.sh builds and logs, verbatim')
    test.set_defaults(func=cmd_test)

    publish = commands.add_parser(
        'publish', parents=[common], description=PUBLISH_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help='tag, sign and publish the prepared release')
    publish.add_argument('--branch',
                         help='branch to release, from a checkout that carries'
                              ' the signing key (default: the checked-out'
                              ' branch)')
    publish.add_argument('--remote', default='origin',
                         help='remote to push the tag to (default: origin)')
    publish.add_argument('--output-dir', default=OUTPUT_DIR,
                         help='where to extract and pack (default: %(default)s)')
    publish.add_argument('--pages-dir',
                         default=str(REPO_ROOT.parent / 'libfuse.github.io'),
                         help='libfuse.github.io checkout, cloned when absent')
    publish.add_argument('--work-dir',
                         help='where test/ci-build.sh builds and logs, verbatim')
    publish.add_argument('--skip-test', action='store_true',
                         help='do not build and test the tarball')
    publish.add_argument('--skip-workflow', action='store_true',
                         help='do not ask about the release workflow run')
    publish.add_argument('--skip-docs', action='store_true',
                         help='do not update the API documentation')
    publish.set_defaults(func=cmd_publish)

    args = parser.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError as error:
        # A failing test build is an ordinary outcome, not a bug in this
        # script.  The command has printed why already.
        fail('%s exited %d' % (shown(error.cmd), error.returncode))


if __name__ == '__main__':
    main()
