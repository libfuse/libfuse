#!/usr/bin/env python3
"""Prepare, build and publish a libfuse release."""

import argparse
import re
import shlex
import shutil
import subprocess
import sys
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


def require_tool(name):
    """Fail unless an external program is installed."""
    if shutil.which(name) is None:
        fail(name + ' is not installed')


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


def require_clean_worktree():
    """Fail unless the libfuse checkout has no modified tracked file."""
    if not worktree_is_clean():
        fail('the working tree has uncommitted changes')


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


def read_version():
    """Return the version the checkout declares."""
    return version_in((REPO_ROOT / 'meson.build').read_text())


def file_at(commit, path):
    """Return a tracked file as of a commit."""
    return git('show', '%s:%s' % (commit, path))


def version_at(commit):
    """Return the version a commit declares."""
    return version_in(file_at(commit, 'meson.build'))


def write_version(version):
    """Replace the version meson.build declares."""
    path = REPO_ROOT / 'meson.build'
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


def is_rst_underline(line):
    """Return whether a line is the '=' rule below a heading."""
    return line != '' and line == '=' * len(line)


def find_unreleased_heading():
    """Return the ChangeLog.rst line index of the Unreleased Changes heading."""
    lines = (REPO_ROOT / 'ChangeLog.rst').read_text().splitlines()
    for index in range(len(lines) - 1):
        if lines[index] == UNRELEASED_HEADING and is_rst_underline(lines[index + 1]):
            return index
    fail('ChangeLog.rst has no "%s" section' % UNRELEASED_HEADING)


def changelog_heading(version, today):
    """Return the ChangeLog.rst heading of one release."""
    return 'libfuse %s (%s)' % (version, today)


def close_changelog(version, today):
    """Rename the Unreleased Changes heading to the one of this release."""
    index = find_unreleased_heading()
    path = REPO_ROOT / 'ChangeLog.rst'
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


def known_author_mails():
    """Return the lower-cased mail addresses AUTHORS already lists."""
    known = set()
    for match in MAIL_IN_ANGLES.finditer((REPO_ROOT / 'AUTHORS').read_text()):
        known.add(match.group(1).lower())
    return known


def new_authors(prev_tag):
    """Return every author since a tag that AUTHORS does not list yet."""
    known = known_author_mails()
    added = []
    listing = git('log', '--format=%aN <%aE>', prev_tag + '..HEAD')
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


def extend_authors(prev_tag, added):
    """Append authors to AUTHORS, under a heading naming the previous tag."""
    path = REPO_ROOT / 'AUTHORS'
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


def missing_signing_keys(version):
    """Return the next release's key basenames whose public half is absent.

    Both successors are returned.  X.Y.0 is followed by X.<Y+1>.0 or by
    <X+1>.0.0, and the tarball has to carry the key of whichever it becomes.
    """
    major, minor = version.split('.')[:2]
    names = ['fuse-%s.%d' % (major, int(minor) + 1),
             'fuse-%d.0' % (int(major) + 1)]
    missing = []
    for name in names:
        if not (REPO_ROOT / 'signify' / (name + '.pub')).exists():
            missing.append(name)
    return missing


def signing_key_commands(name):
    """Return the commands that generate a signing key and stage its .pub."""
    public = REPO_ROOT / 'signify' / (name + '.pub')
    secret = REPO_ROOT / 'signify' / (name + '.sec')
    return [['signify-openbsd', '-G', '-n', '-p', str(public), '-s', str(secret)],
            ['git', 'add', str(public)]]


def create_signing_key(name):
    """Generate a signing key and stage its public half."""
    for argv in signing_key_commands(name):
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
    require_tool('doxygen')
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
    """Return the branch to release and the commit it points at."""
    current = git('rev-parse', '--abbrev-ref', 'HEAD')
    if current == 'HEAD':
        fail('HEAD is detached; check out the branch to release, or master')
    # The signing keys are read from the checkout.  master carries all of
    # them.
    if wanted is not None and wanted != current and current != 'master':
        fail('--branch %s needs master checked out, %s is checked out'
             % (wanted, current))
    branch = wanted or current
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


def cmd_prepare(args):
    """Make the "Released ..." commit the release pull request carries."""
    require_clean_worktree()
    version = args.version
    if re.fullmatch(r'\d+\.\d+\.\d+', version) is None:
        fail('version must be MAJOR.MINOR.PATCH, got ' + version)
    tag = 'fuse-' + version
    if tag_exists(tag):
        fail(tag + ' exists already')
    prev_tag = previous_tag(version)

    # Everything that can refuse the release runs before the first edit.  A
    # refused one leaves no half-prepared tree behind.
    old_version = read_version()
    find_unreleased_heading()
    missing_keys = missing_signing_keys(version)
    # A patch release inherits the keys its .0 generated.  A missing one may
    # be published already.  A second key of that name looks the same to
    # whoever verifies with the first.
    if missing_keys and version.split('.')[2] != '0' and not args.new_key:
        fail('signify/%s.pub is missing; restore the backup, or pass --new-key'
             ' to generate a new key' % missing_keys[0])
    if missing_keys:
        require_tool('signify-openbsd')
    added = new_authors(prev_tag)
    today = date.today().isoformat()
    commit_argv = ['git', 'commit', '-s', '--all', '-m', 'Released ' + tag]

    print("meson.build:   version: '%s' -> version: '%s'"
          % (old_version, version))
    print('ChangeLog.rst: %s -> %s'
          % (UNRELEASED_HEADING, changelog_heading(version, today)))
    if len(added) == 0:
        print('AUTHORS:       no new authors since ' + prev_tag)
    for line in added:
        print('AUTHORS:       + ' + line)
    for key_name in missing_keys:
        for argv in signing_key_commands(key_name):
            print('+ ' + shown(argv))
    print('+ ' + shown(commit_argv))
    if not args.dry_run:
        write_version(version)
        close_changelog(version, today)
        if len(added) > 0:
            extend_authors(prev_tag, added)
        for key_name in missing_keys:
            create_signing_key(key_name)
        run(commit_argv)

    branch = git('rev-parse', '--abbrev-ref', 'HEAD')
    push_argv = ['git', 'push', args.remote, branch]
    if step(args.dry_run, 'Push the release branch:', shown(push_argv)):
        run(push_argv)

    print('')
    print('Prepared %s on top of %s.' % (tag, prev_tag))
    print('Open the pull request:')
    print('    ' + compare_url(args.base, branch))
    print('Once it is merged:')
    print('    git checkout ' + args.base)
    print('    %s publish' % sys.argv[0])
    if args.dry_run:
        print('')
        print('nothing was changed')


def cmd_tarball(args):
    """Build the release tarball of a commit and print its path."""
    if not succeeds(['git', 'rev-parse', '-q', '--verify',
                     args.commit + '^{commit}']):
        fail('no such commit: ' + args.commit)
    output_dir = Path(args.output_dir).resolve()
    if args.dry_run:
        require_tool('doxygen')
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
    require_tool('signify-openbsd')
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
                                  and the keys of the next release
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
Set the version in meson.build, close the Unreleased Changes section of
ChangeLog.rst, add the new authors to AUTHORS, generate the signing keys
the next release needs, and commit all of it as "Released fuse-<version>".
Run this on the branch whose pull request carries the release.

The push of that branch is offered and can be skipped.  Opening the pull
request and merging it are done by hand, and the URL is printed.
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
it is offered when it does not.  Releasing another branch than the
checked-out one needs master, which carries the keys.
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
    prepare.add_argument('--remote', default='origin',
                         help='remote to push the branch to (default: origin)')
    prepare.add_argument('--base', default='master',
                         help='branch the pull request merges into'
                              ' (default: master)')
    prepare.add_argument('--new-key', action='store_true',
                         help='generate a missing next-release key in a patch'
                              ' release')
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
                         help='branch to release, master checked out'
                              ' (default: the checked-out branch)')
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
