#!/usr/bin/env python3
"""Check what scripts/release.py decides during a publish.

The script reaches the outside world through output(), run(), succeeds() and
confirm().  Every case here replaces those four, so a whole publish runs with
no repository, no remote, no GitHub, no doxygen and no signify.
"""

import importlib.util
import io
import subprocess
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


def load_release():
    """Import scripts/release.py, which is a program and not a package."""
    path = Path(__file__).resolve().parent.parent / 'scripts' / 'release.py'
    spec = importlib.util.spec_from_file_location('release', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_release()

REMOTE = 'origin'
BRANCH = 'fuse-3.18.x'
# A branch of master, which is where a release is published from.
WORK_BRANCH = 'release-tooling'
COMMIT = 'a' * 40
OTHER_COMMIT = 'b' * 40
# An annotated tag's own object.  ls-remote reports it for refs/tags/<tag>,
# and it is never the commit a release is cut from.
TAG_OBJECT = 'c' * 40
VERSION = '3.18.3'
TAG = 'fuse-' + VERSION
# What a release branch names its open section before the release goes out.
RC_VERSION = VERSION + '-rc1'
# What a checkout declares before prepare sets the version being released.
DEVELOPMENT_VERSION = '3.19.0-rc0'

MESON = """\
project('libfuse', ['c'],
	version: '%s',
	meson_version: '>= 0.51'
)
"""

CHANGE = '* Stopped reusing the tarball of another commit.'

AUTHOR = 'Bernd Schubert <bernd@example.com>'


def changelog_entry(version, day, change):
    """Return one ChangeLog.rst section, its heading and rule included."""
    heading = 'libfuse %s (%s)' % (version, day)
    return '%s\n%s\n\n%s\n' % (heading, '=' * len(heading), change)


# Built from VERSION.  A version written out here again is one more place to
# edit, and changelog_section() finds nothing when the two disagree.
CHANGELOG = (changelog_entry(VERSION, '2026-09-07', CHANGE) + '\n'
             + changelog_entry('3.18.2', '2026-08-01', '* Something else.'))

# What a checkout carries before prepare closes the section.  The rule is as
# long as the heading, which is all find_unreleased_heading() asks.
UNRELEASED = '%s\n%s\n\n%s\n\n' % (release.UNRELEASED_HEADING,
                                   '=' * len(release.UNRELEASED_HEADING),
                                   CHANGE)

# Every entry is older than VERSION, which is all previous_tag() asks.
TAG_LIST = 'fuse-3.17.0\nfuse-3.18.1\nfuse-3.18.2'

def tag_rows(commit):
    """Return the ls-remote rows of an annotated tag at a commit."""
    return '%s\trefs/tags/%s\n%s\trefs/tags/%s^{}' % (TAG_OBJECT, TAG,
                                                      commit, TAG)


class FakeGit:
    """Answer the git commands a publish runs, and record the ones it makes."""

    def __init__(self, remote_tag_rows='', local_commit=COMMIT,
                 remote_commit=None, local_tag=False):
        self.remote_tag_rows = remote_tag_rows
        # What HEAD has out, which is not the branch being released once a
        # case says otherwise.  'HEAD' is a detached one.
        self.head_branch = BRANCH
        self.local_commit = local_commit
        # The two are the same until a case says the remote is ahead.  Empty
        # is a remote without the branch at all.
        self.remote_commit = (local_commit if remote_commit is None
                              else remote_commit)
        self.local_tag = local_tag
        # The program a case says exits non-zero, e.g. a build that fails.
        self.fails_at = ''
        self.ran = []

    def output(self, argv, cwd=None):
        rest = argv[1:]
        if rest == ['rev-parse', '--abbrev-ref', 'HEAD']:
            return self.head_branch
        if rest == ['rev-parse', 'refs/heads/' + BRANCH]:
            return self.local_commit
        if rest == ['rev-parse', TAG + '^{commit}']:
            return self.local_commit
        if rest[0] == 'ls-remote':
            if any(ref.startswith('refs/tags/') for ref in rest[2:]):
                return self.remote_tag_rows
            if self.remote_commit == '':
                return ''
            return '%s\trefs/heads/%s' % (self.remote_commit, BRANCH)
        if rest[0] == 'show' and rest[1].endswith(':meson.build'):
            return MESON % VERSION
        if rest[0] == 'show' and rest[1].endswith(':ChangeLog.rst'):
            return CHANGELOG
        if rest[:2] == ['tag', '--list']:
            return TAG_LIST
        if rest[0] == 'log':
            return AUTHOR
        if rest[0] == 'status':
            return ''
        raise AssertionError('unexpected git command: ' + ' '.join(argv))

    def run(self, argv, cwd=None):
        self.ran.append(argv)
        if self.fails_at != '' and argv[0] == self.fails_at:
            raise subprocess.CalledProcessError(1, argv)
        # The fast-forward is what moves the local branch onto the commit the
        # remote has.  Everything cmd_publish() does afterwards reads that one.
        if argv[:2] == ['git', 'pull'] or argv[:2] == ['git', 'fetch']:
            self.local_commit = self.remote_commit

    def succeeds(self, argv, cwd=None):
        if argv[-1].startswith('refs/tags/'):
            return self.local_tag
        return True


class ScriptCase(unittest.TestCase):
    """Run one release.py command with what it reaches outside replaced."""

    def setUp(self):
        # What the command asked for, and what a case says is not installed.
        self.wanted_tools = []
        self.missing_tools = []
        # What the last call wrote to stderr, which is where fail() reports.
        self.errors = ''

    def have_tools(self, names):
        """Answer the tool check the way a case says the machine looks."""
        self.wanted_tools = names
        for name in names:
            if name in self.missing_tools:
                release.fail('not installed: ' + name)

    def replace(self, name, value):
        """Put a stub in the module and restore the original afterwards."""
        self.addCleanup(setattr, release, name, getattr(release, name))
        setattr(release, name, value)

    def checkout(self):
        """Return the checkout the script reads and writes instead of its own."""
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        root = Path(base.name)
        (root / 'signify').mkdir()
        self.replace('REPO_ROOT', root)
        return root

    def options(self, defaults, changes):
        """Return the options of one command, with what a case changes."""
        for name, value in changes.items():
            setattr(defaults, name, value)
        return defaults

    def call(self, command, args):
        """Run one command and return what it printed."""
        printed = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(printed), redirect_stderr(errors):
            command(args)
        self.errors = errors.getvalue()
        return printed.getvalue()

    def call_exits(self, command, args, code):
        """Run one command that has to leave with a status of its own."""
        printed = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(printed), redirect_stderr(errors):
            with self.assertRaises(SystemExit) as left:
                command(args)
        self.assertEqual(left.exception.code, code)
        self.errors = errors.getvalue()
        return printed.getvalue()


class PublishCase(ScriptCase):
    """A cmd_publish() run with everything outside the script replaced."""

    def setUp(self):
        super().setUp()
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.output_dir = Path(base.name) / 'release'
        self.output_dir.mkdir()
        self.git = FakeGit()
        self.packed = []
        self.tested = []
        self.questions = []

        self.replace('output', self.git.output)
        self.replace('run', self.git.run)
        self.replace('succeeds', self.git.succeeds)
        self.replace('confirm', self.answer)
        self.replace('require_tools', self.have_tools)
        self.replace('signing_key', lambda tag: Path('/nonexistent/key.sec'))
        self.replace('build_tarball', self.pack)
        self.replace('test_tarball', self.record_test)
        self.replace('update_api_docs', lambda tag, work, pages: False)

    def answer(self, question):
        self.questions.append(question)
        return True

    def pack(self, commit, output_dir):
        self.packed.append((commit, output_dir))
        return output_dir / (TAG + '.tar.gz')

    def record_test(self, tarball, verify_dir, work_dir):
        self.tested.append(tarball)

    def leave_artifacts(self):
        """Leave the tarball and the extracted tree of an earlier attempt."""
        (self.output_dir / (TAG + '.tar.gz')).write_text('an older commit\n')
        (self.output_dir / TAG).mkdir()

    def args(self, **changes):
        return self.options(
            Namespace(dry_run=False, branch=None, remote=REMOTE,
                      output_dir=str(self.output_dir),
                      pages_dir=str(self.output_dir / 'pages'),
                      work_dir=None, skip_test=False, skip_workflow=False,
                      skip_docs=True),
            changes)

    def publish(self, **changes):
        """Run a publish and return what it printed."""
        return self.call(release.cmd_publish, self.args(**changes))

    def publish_fails(self, **changes):
        """Run a publish that has to end with a non-zero status."""
        return self.call_exits(release.cmd_publish, self.args(**changes), 1)

    def publish_stops(self, **changes):
        """Run a publish that a no ends, which is not a failure."""
        return self.call_exits(release.cmd_publish, self.args(**changes), 0)

    def assertAsksForWorkflow(self, printed):
        self.assertIn(release.RELEASE_WORKFLOW, printed)

    def assertNoWorkflowQuestion(self, printed):
        self.assertNotIn(release.RELEASE_WORKFLOW, printed)

    def pushed_the_tag(self):
        return ['git', 'push', REMOTE, 'refs/tags/' + TAG] in self.git.ran


class RemoteTagCommit(unittest.TestCase):
    """remote_tag_commit() reads what a remote tag points at."""

    def rows(self, listing):
        self.addCleanup(setattr, release, 'output', release.output)
        release.output = lambda argv, cwd=None: listing

    def test_annotated_tag_returns_the_peeled_commit(self):
        self.rows(tag_rows(COMMIT))
        self.assertEqual(release.remote_tag_commit(REMOTE, TAG), COMMIT)

    def test_lightweight_tag_returns_the_row_it_has(self):
        self.rows('%s\trefs/tags/%s' % (COMMIT, TAG))
        self.assertEqual(release.remote_tag_commit(REMOTE, TAG), COMMIT)

    def test_missing_tag_returns_nothing(self):
        self.rows('')
        self.assertEqual(release.remote_tag_commit(REMOTE, TAG), '')


class Artifacts(PublishCase):
    """The tarball and the extracted tree belong to the commit being tagged."""

    def test_existing_artifacts_are_rebuilt(self):
        # Their names carry the version, so an earlier commit of the same
        # version leaves them exactly where this run looks.
        self.leave_artifacts()
        self.publish()
        self.assertEqual(self.packed, [(COMMIT, self.output_dir)])

    def test_the_tested_tarball_is_the_one_just_packed(self):
        self.leave_artifacts()
        self.publish()
        self.assertEqual(self.tested, [self.output_dir / (TAG + '.tar.gz')])


class Branch(PublishCase):
    """What the remote has the branch at decides what is released."""

    def test_a_branch_behind_the_remote_is_released_from_the_remote_commit(self):
        self.git.remote_commit = OTHER_COMMIT
        self.publish()
        self.assertIn(['git', 'pull', '--ff-only', REMOTE, BRANCH],
                      self.git.ran)
        # Everything after the fast-forward names the commit it moved to.
        self.assertEqual(self.packed, [(OTHER_COMMIT, self.output_dir)])
        self.assertIn(['git', 'tag', '-s', '-m', TAG, TAG, OTHER_COMMIT],
                      self.git.ran)

    def test_a_refused_update_ends_the_release(self):
        self.git.remote_commit = OTHER_COMMIT
        self.replace('confirm', lambda question: False)
        self.publish_stops()
        self.assertEqual(self.git.ran, [])
        self.assertEqual(self.packed, [])

    def test_a_branch_the_remote_does_not_have_stops_the_release(self):
        self.git.remote_commit = ''
        self.publish_fails()
        self.assertEqual(self.git.ran, [])
        self.assertEqual(self.packed, [])


class Checkout(PublishCase):
    """Which checkout may release a branch."""

    def test_a_branch_of_master_releases_another_branch(self):
        self.git.head_branch = WORK_BRANCH
        self.publish(branch=BRANCH)
        self.assertIn(['git', 'tag', '-s', '-m', TAG, TAG, COMMIT],
                      self.git.ran)

    def test_a_detached_head_releases_the_branch_it_is_given(self):
        self.git.head_branch = 'HEAD'
        self.publish(branch=BRANCH)
        self.assertIn(['git', 'tag', '-s', '-m', TAG, TAG, COMMIT],
                      self.git.ran)

    def test_a_detached_head_with_no_branch_named_fails(self):
        self.git.head_branch = 'HEAD'
        self.publish_fails()
        self.assertEqual(self.git.ran, [])


class RemoteTag(PublishCase):
    """What the remote tag points at decides how the publish goes on."""

    def test_absent_tag_asks_for_the_workflow_and_pushes(self):
        printed = self.publish()
        self.assertAsksForWorkflow(printed)
        self.assertTrue(self.pushed_the_tag())

    def test_tag_at_the_release_commit_skips_the_workflow_and_the_push(self):
        self.git.remote_tag_rows = tag_rows(COMMIT)
        printed = self.publish()
        self.assertNoWorkflowQuestion(printed)
        self.assertFalse(self.pushed_the_tag())
        self.assertEqual(self.packed, [(COMMIT, self.output_dir)])

    def test_tag_at_another_commit_stops_before_anything_happens(self):
        self.git.remote_tag_rows = tag_rows(OTHER_COMMIT)
        printed = self.publish_fails()
        self.assertEqual(self.packed, [])
        self.assertEqual(self.git.ran, [])
        self.assertNoWorkflowQuestion(printed)

    def test_tag_at_another_commit_stops_the_skipped_run_too(self):
        # The flags a retry after a failed publish carries must not reach the
        # check.
        self.git.remote_tag_rows = tag_rows(OTHER_COMMIT)
        self.publish_fails(skip_test=True, skip_workflow=True)
        self.assertEqual(self.packed, [])
        self.assertEqual(self.git.ran, [])


class Reading(unittest.TestCase):
    """What the script reads out of a commit."""

    def test_version_comes_from_the_meson_build_line(self):
        self.assertEqual(release.version_in(MESON % VERSION), VERSION)

    def test_previous_tag_is_the_newest_older_version(self):
        self.addCleanup(setattr, release, 'output', release.output)
        release.output = lambda argv, cwd=None: TAG_LIST
        self.assertEqual(release.previous_tag(VERSION), 'fuse-3.18.2')

    def test_changelog_section_is_one_release(self):
        section = release.changelog_section(VERSION, CHANGELOG)
        self.assertEqual(section, CHANGE)

    def test_a_patch_release_signs_with_the_key_of_its_series(self):
        self.assertEqual(release.signify_key_name(TAG), 'fuse-3.18')


class RequiredTools(ScriptCase):
    """require_tools() names every program a command needs and lacks."""

    def test_an_installed_program_passes(self):
        release.require_tools(['sh'])

    def test_every_missing_program_is_named_at_once(self):
        printed = io.StringIO()
        with redirect_stderr(printed):
            with self.assertRaises(SystemExit) as left:
                release.require_tools(['sh', 'not-a-program-x',
                                       'not-a-program-y'])
        self.assertEqual(left.exception.code, 1)
        self.assertIn('not-a-program-x, not-a-program-y', printed.getvalue())


class Tools(PublishCase):
    """A publish checks its programs before it does anything."""

    def test_the_tools_are_checked_before_the_first_question(self):
        self.publish()
        self.assertEqual(self.wanted_tools, ['doxygen', 'signify-openbsd'])

    def test_a_missing_tool_ends_the_release_before_anything_runs(self):
        self.missing_tools = ['doxygen']
        self.publish_fails()
        self.assertEqual(self.questions, [])
        self.assertEqual(self.git.ran, [])
        self.assertEqual(self.packed, [])


class SigningKey(ScriptCase):
    """Which key a release has to generate before it is cut."""

    def setUp(self):
        super().setUp()
        self.root = self.checkout()

    def carry(self, name):
        """Put a key's public half in the checkout, as a release commit does."""
        (self.root / 'signify' / (name + '.pub')).write_text('untrusted\n')

    def test_a_patch_release_generates_nothing(self):
        self.assertEqual(release.missing_signing_key(self.root, VERSION, False),
                         '')

    def test_a_minor_release_generates_the_next_minor(self):
        self.assertEqual(release.missing_signing_key(self.root, '3.19.0',
                                                     False), 'fuse-3.20')

    def test_a_key_the_checkout_carries_is_not_generated_again(self):
        self.carry('fuse-3.20')
        self.assertEqual(release.missing_signing_key(self.root, '3.19.0',
                                                     False), '')

    def test_a_forced_patch_release_generates_the_next_minor(self):
        self.assertEqual(release.missing_signing_key(self.root, '3.19.1',
                                                     True), 'fuse-3.20')


def unreleased_version_section(version):
    """Return the open section a release branch heads with its version."""
    heading = 'libfuse %s (unreleased)' % version
    return '%s\n%s\n\n%s\n\n' % (heading, '=' * len(heading), CHANGE)


class UnreleasedHeading(ScriptCase):
    """Which ChangeLog.rst heading names the section a release closes."""

    def setUp(self):
        super().setUp()
        self.root = self.checkout()

    def find(self, changelog):
        (self.root / 'ChangeLog.rst').write_text(changelog)
        return release.find_unreleased_heading(self.root)

    def test_the_unreleased_changes_heading_is_found(self):
        index, heading = self.find(UNRELEASED + CHANGELOG)
        self.assertEqual(index, 0)
        self.assertEqual(heading, release.UNRELEASED_HEADING)

    def test_an_unreleased_version_heading_is_found_too(self):
        index, heading = self.find(unreleased_version_section(RC_VERSION)
                                   + CHANGELOG)
        self.assertEqual(index, 0)
        self.assertEqual(heading, 'libfuse %s (unreleased)' % RC_VERSION)

    def test_a_reopened_section_is_found_under_the_release_version(self):
        index, heading = self.find(unreleased_version_section(VERSION)
                                   + CHANGELOG)
        self.assertEqual(index, 0)
        self.assertEqual(heading, 'libfuse %s (unreleased)' % VERSION)

    def test_released_sections_alone_are_no_open_section(self):
        self.assertEqual(self.find(CHANGELOG), (-1, ''))


class PrepareCase(ScriptCase):
    """A cmd_prepare() run against a checkout of the files it edits."""

    def setUp(self):
        super().setUp()
        self.root = self.checkout()
        self.fill(self.root)
        self.git = FakeGit()
        self.questions = []
        # The question a case answers with a no.  Every other one gets a yes.
        self.refused = ''
        self.generated = []
        self.added = ''
        self.removed = None

        self.replace('output', self.git.output)
        self.replace('run', self.git.run)
        self.replace('succeeds', self.git.succeeds)
        self.replace('confirm', self.answer)
        self.replace('require_tools', self.have_tools)
        self.replace('create_signing_key', self.generate)

    def fill(self, root):
        """Write the three files a release edits into a checkout."""
        (root / 'signify').mkdir(exist_ok=True)
        (root / 'meson.build').write_text(MESON % DEVELOPMENT_VERSION)
        (root / 'ChangeLog.rst').write_text(UNRELEASED + CHANGELOG)
        (root / 'AUTHORS').write_text(AUTHOR + '\n')

    def use_worktree(self):
        """Stand a second checkout in for the one --branch checks out."""
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.worktree = Path(base.name) / 'checkout'
        self.worktree.mkdir()
        self.fill(self.worktree)
        self.replace('add_worktree', self.add)
        self.replace('remove_worktree', self.remove)
        return self.worktree

    def add(self, branch):
        self.added = branch
        return self.worktree

    def remove(self, root):
        self.removed = root

    def answer(self, question):
        self.questions.append(question)
        if self.refused != '' and self.refused in question:
            return False
        return True

    def generate(self, root, name):
        self.generated.append(name)

    def args(self, **changes):
        return self.options(
            Namespace(dry_run=False, version=VERSION, branch=None,
                      remote=REMOTE, base='master', skip_test=False,
                      force_new_version=False),
            changes)

    def build_index(self):
        """Return where the build ran among the commands, -1 when it did not."""
        for index in range(len(self.git.ran)):
            if self.git.ran[index][0] == 'ninja':
                return index
        return -1

    def prepare(self, **changes):
        """Run a prepare and return what it printed."""
        return self.call(release.cmd_prepare, self.args(**changes))

    def prepare_stops(self, **changes):
        """Run a prepare that a no ends, which is not a failure."""
        return self.call_exits(release.cmd_prepare, self.args(**changes), 0)

    def prepare_fails(self, **changes):
        """Run a prepare that has to end with a non-zero status."""
        return self.call_exits(release.cmd_prepare, self.args(**changes), 1)

    def asked_for(self, key_name):
        return release.next_version_question(key_name) in self.questions


class NextVersionKey(PrepareCase):
    """The key of the next version is generated once someone agrees to it."""

    def test_a_patch_release_asks_nothing_and_generates_nothing(self):
        self.prepare()
        self.assertEqual(self.generated, [])
        self.assertFalse(self.asked_for('fuse-3.19'))

    def test_a_minor_release_asks_for_the_next_version(self):
        self.prepare(version='3.19.0')
        self.assertTrue(self.asked_for('fuse-3.20'))
        self.assertEqual(self.generated, ['fuse-3.20'])

    def test_a_no_to_the_next_version_writes_nothing(self):
        self.refused = release.next_version_question('fuse-3.20')
        self.prepare_stops(version='3.19.0')
        self.assertEqual(self.generated, [])
        self.assertEqual(release.read_version(self.root), DEVELOPMENT_VERSION)
        self.assertEqual(self.git.ran, [])

    def test_force_new_version_generates_the_key_of_a_patch_release(self):
        # 3.19.0 was never released, so nothing generated fuse-3.20 yet.
        self.prepare(version='3.19.1', force_new_version=True)
        self.assertTrue(self.asked_for('fuse-3.20'))
        self.assertEqual(self.generated, ['fuse-3.20'])

    def test_a_dry_run_asks_nothing_and_writes_nothing(self):
        printed = self.prepare(version='3.19.0', dry_run=True)
        self.assertIn(release.next_version_question('fuse-3.20'), printed)
        self.assertEqual(self.questions, [])
        self.assertEqual(self.generated, [])
        self.assertEqual(release.read_version(self.root), DEVELOPMENT_VERSION)


class Changelog(PrepareCase):
    """prepare closes the section the checkout has open, however it is named."""

    def test_an_unreleased_version_heading_is_closed_to_this_release(self):
        (self.root / 'ChangeLog.rst').write_text(
            unreleased_version_section(RC_VERSION) + CHANGELOG)
        printed = self.prepare()
        closed = (self.root / 'ChangeLog.rst').read_text()
        self.assertIn('libfuse %s (' % VERSION, closed)
        self.assertNotIn('(unreleased)', closed)
        # The report names the heading the checkout carried, not the one
        # master would have had.
        self.assertIn('libfuse %s (unreleased) ->' % RC_VERSION, printed)

    def test_the_entries_below_the_heading_are_left_alone(self):
        (self.root / 'ChangeLog.rst').write_text(
            unreleased_version_section(RC_VERSION) + CHANGELOG)
        self.prepare()
        closed = (self.root / 'ChangeLog.rst').read_text()
        self.assertEqual(release.changelog_section(VERSION, closed), CHANGE)


class BuildBeforeCommitting(PrepareCase):
    """The branch is built before the release commit is written."""

    def test_the_build_runs_and_the_commit_comes_after_it(self):
        self.prepare()
        index = self.build_index()
        self.assertNotEqual(index, -1)
        # Nothing was committed or pushed while the build was still to come.
        for argv in self.git.ran[:index]:
            self.assertNotIn('commit', argv)
            self.assertNotIn('push', argv)

    def test_the_build_has_warnings_fatal(self):
        self.prepare()
        setup = ['meson', 'setup', '-Dwerror=true',
                 str(Path(release.OUTPUT_DIR) / 'prepare-build'),
                 str(self.root)]
        self.assertIn(setup, self.git.ran)

    def test_a_failing_build_writes_nothing(self):
        self.git.fails_at = 'ninja'
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare()
        self.assertEqual(release.read_version(self.root), DEVELOPMENT_VERSION)
        self.assertIn(release.UNRELEASED_HEADING,
                      (self.root / 'ChangeLog.rst').read_text())

    def test_skip_test_leaves_the_build_out(self):
        self.prepare(skip_test=True)
        self.assertEqual(self.build_index(), -1)
        self.assertEqual(self.wanted_tools, [])

    def test_the_build_tools_are_checked_up_front(self):
        self.prepare()
        self.assertEqual(self.wanted_tools, ['meson', 'ninja'])


class Prepared(PrepareCase):
    """A release the branch carries already is not prepared a second time."""

    def carry_the_release(self, root):
        """Leave a checkout the way a release commit leaves it."""
        (root / 'meson.build').write_text(MESON % VERSION)
        (root / 'ChangeLog.rst').write_text(CHANGELOG)

    def test_a_branch_that_carries_the_release_is_not_prepared_again(self):
        self.carry_the_release(self.root)
        self.prepare_fails()
        self.assertIn('carries %s already' % VERSION, self.errors)
        self.assertEqual(self.git.ran, [])

    def test_the_publish_that_is_left_is_named(self):
        worktree = self.use_worktree()
        self.carry_the_release(worktree)
        self.prepare_fails(branch=BRANCH)
        self.assertIn('publish --branch ' + BRANCH, self.errors)

    def test_the_closed_changelog_is_not_what_it_reports(self):
        self.carry_the_release(self.root)
        self.prepare_fails()
        self.assertNotIn('ChangeLog.rst', self.errors)

    def test_a_section_reopened_after_the_release_commit_is_prepared_again(self):
        # A backport landed on the release branch and re-opened the section.
        # meson.build still declares the version, which is not what decides.
        (self.root / 'meson.build').write_text(MESON % VERSION)
        (self.root / 'ChangeLog.rst').write_text(
            unreleased_version_section(VERSION) + CHANGELOG)
        self.prepare()
        closed = (self.root / 'ChangeLog.rst').read_text()
        self.assertNotIn('(unreleased)', closed)
        self.assertIn('libfuse %s (' % VERSION, closed)

    def test_a_changelog_with_no_open_section_at_all_reports_the_changelog(self):
        (self.root / 'ChangeLog.rst').write_text(CHANGELOG)
        self.prepare_fails(version='3.18.4')
        self.assertIn('ChangeLog.rst', self.errors)


class PrepareBranch(PrepareCase):
    """--branch releases a branch the script does not have checked out."""

    def test_the_release_is_written_and_committed_in_the_added_checkout(self):
        worktree = self.use_worktree()
        self.prepare(branch=BRANCH)
        self.assertEqual(self.added, BRANCH)
        self.assertIn(['git', '-C', str(worktree), 'commit', '-s', '--all',
                       '-m', 'Released ' + TAG], self.git.ran)
        self.assertEqual(release.read_version(worktree), VERSION)

    def test_the_checkout_the_script_runs_in_is_left_alone(self):
        self.use_worktree()
        self.prepare(branch=BRANCH)
        self.assertEqual(release.read_version(self.root), DEVELOPMENT_VERSION)

    def test_the_added_checkout_is_taken_out_again(self):
        worktree = self.use_worktree()
        self.prepare(branch=BRANCH)
        self.assertEqual(self.removed, worktree)

    def test_the_added_checkout_is_taken_out_when_the_release_stops(self):
        worktree = self.use_worktree()
        self.refused = release.next_version_question('fuse-3.20')
        self.prepare_stops(branch=BRANCH, version='3.19.0')
        self.assertEqual(self.removed, worktree)

    def test_a_branch_behind_the_remote_is_brought_up_first(self):
        self.use_worktree()
        self.git.remote_commit = OTHER_COMMIT
        self.prepare(branch=BRANCH)
        self.assertIn(['git', 'fetch', REMOTE, '%s:%s' % (BRANCH, BRANCH)],
                      self.git.ran)

    def test_the_release_is_published_from_the_branch_not_a_pull_request(self):
        self.use_worktree()
        printed = self.prepare(branch=BRANCH)
        self.assertNotIn('/compare/', printed)
        self.assertIn('publish --branch ' + BRANCH, printed)


if __name__ == '__main__':
    unittest.main()
