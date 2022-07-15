#!/usr/bin/env python3
from argparse import ArgumentParser
from subprocess import call
from time import gmtime, strftime

import json
import logging as log
import os
import re
import sys
import tempfile
import yaml

# Local files
from jipdate import cfg
from jipdate import jiralogin

################################################################################
# Helper functions
################################################################################
def print_status(status):
    """ Helper function printing your status """
    print("This is your status:")
    print("\n---\n")
    print("\n".join(l.strip('\n') for l in status))


def open_editor(filename):
    """
    Function that tries to find the best suited editor to use and then
    opens the status file in the editor.
    """
    if "EDITOR" in os.environ:
        editor = os.environ['EDITOR']
    elif "VISUAL" in os.environ:
        editor = os.environ['VISUAL']
    elif os.path.exists("/usr/bin/editor"):
        editor = "/usr/bin/editor"
    elif os.path.exists("/usr/bin/vim"):
        editor = "/usr/bin/vim"
    elif os.path.exists("/usr/bin/vi"):
        editor = "/usr/bin/vi"
    else:
        log.error("Could not load an editor.  Please define EDITOR or VISUAL")
        sys.exit(os.EX_CONFIG)

    call(editor.split() + [filename])


def open_file(filename):
    """
    This will open the user provided file and if there has not been any file
    provided it will create and open a temporary file instead.
    """
    log.debug("filename: %s\n" % filename)
    if filename:
        return open(filename, "w")
    else:
        return tempfile.NamedTemporaryFile(mode='w+t', delete=False)


def add_domain(user):
    """
    Helper function that appends @linaro.org to the username. It does nothing if
    it is already included.
    """
    if '@' not in user:
        user = user + "@linaro.org"
    return user


def email_to_name(email):
    """ Converts 'first.last@linaro.org' to 'First Last'. """
    n = email.split("@")[0].title()
    return n.replace(".", " ")

################################################################################
# Argument parser
################################################################################
def get_parser():
    """ Takes care of script argument parsing. """
    parser = ArgumentParser(description='Script used to create tickets in Jira')

    parser.add_argument('-f', '--file', required=False, action="store", \
            default=None, \
            help='Create issue from FILE.')

    parser.add_argument('-u', '--user', required=False, action="store", \
            default=None, \
            help='Query Jira with another Jira username \
            (first.last or first.last@linaro.org)')

    parser.add_argument('-v', required=False, action="store_true", \
            default=False, \
            help='Output some verbose debugging info')

    parser.add_argument('--dry-run', required=False, action="store_true", \
            default=False, \
            help='Do not make any changes to JIRA')

    return parser

################################################################################
# Jira functions
################################################################################
def update_jira(jira, i, c, t):
    """
    This is the function that do the actual updates to Jira and in this case it
    is adding comments to a certain issue.
    """
    if t['transition']:
        if t['resolution']:
            log.debug("Updating Jira issue: %s with transition: %s (%s)" %
                   (i, t['transition'], t['resolution']))
            jira.transition_issue(i, t['transition'], fields={'resolution':{'id': t['resolution']}})
        else:
            log.debug("Updating Jira issue: %s with transition: %s" % (i, t['transition']))
            jira.transition_issue(i, t['transition'])

    if c != "":
        log.debug("Updating Jira issue: %s with comment:" % i)
        log.debug("-- 8< --------------------------------------------------------------------------")
        log.debug("%s" % c)
        log.debug("-- >8 --------------------------------------------------------------------------\n\n")
        jira.add_comment(i, c)


def write_last_jira_comment(f, jira, issue):
    """ Pulls the last comment from Jira from an issue and writes it to the file
    object.
    """
    c = jira.comments(issue)
    if len(c) > 0:
        try:
            comment = "# Last comment:\n# ---8<---\n# %s\n# --->8---\n" % \
                        "\n# ".join(c[-1].body.splitlines())
            f.write(comment)
        except UnicodeEncodeError:
            log.debug("Can't encode character")


def get_jira_issues(jira, username):
    """
    Query Jira and then creates a status update file (either temporary or named)
    containing all information found from the JQL query.
    """
    exclude_stories = cfg.args.x
    epics_only = cfg.args.e
    all_status = cfg.args.all
    filename = cfg.args.file
    user = cfg.args.user
    last_comment = cfg.args.l

    issue_types = ["Sub-task", "Epic"]
    if not epics_only:
        issue_types.append("Initiative")
        if not exclude_stories:
            issue_types.extend(["Story", "Sub-task", "Bug"])
    issue_type = "issuetype in (%s)" % ", ".join(issue_types)

    status = "status in (\"In Progress\")"
    if all_status:
        status = "status not in (Resolved, Closed)"

    if user is None:
        user = "currentUser()"
    else:
        user = "\"%s\"" % add_domain(user)

    jql = "%s AND assignee = %s AND %s" % (issue_type, user, status)
    log.debug(jql)

    my_issues = jira.search_issues(jql)
    if my_issues.total > my_issues.maxResults:
        my_issues = jira.search_issues(jql, maxResults=my_issues.total)

    showdate = strftime("%Y-%m-%d", gmtime())
    subject = "Subject: [Weekly] Week ending " + showdate + "\n\n"

    msg = get_header()
    if msg != "":
        msg += email_to_name(username) + "\n\n"

    f = open_file(filename)
    filename = f.name

    f.write(subject)

    f.write(msg)
    log.debug("Found issue:")
    for issue in my_issues:
        log.debug("%s : %s" % (issue, issue.fields.summary))

        if (merge_issue_header()):
            f.write("[%s%s%s]\n" % (issue, get_header_separator(), issue.fields.summary))
        else:
            f.write("[%s]\n" % issue)
            f.write("# Header: %s\n" % issue.fields.summary)

        f.write("# Type: %s\n" % issue.fields.issuetype)
        f.write("# Status: %s\n" % issue.fields.status)
        f.write(get_extra_comments())
        if last_comment:
            write_last_jira_comment(f, jira, issue)
        f.write("\n")

    f.close()
    return (filename, my_issues)


def should_update():
    """ A yes or no dialogue. """
    while True:
        server = cfg.get_server()
        print("Server to update: %s\n" % server.get('url'));
        answer = input("Are you sure you want to update Jira with the " +
                           "information above? [y/n] ").lower().strip()
        if answer in set(['y', 'n']):
            return answer
        else:
            print("Incorrect input: %s" % answer)

def parse_issue_file(new_issue_file):
    """ Reads new issue file and parse it into a python object
    """

    if not os.path.isfile(new_issue_file):
        sys.exit(-1)

    log.debug("Using issue file: %s" % new_issue_file)
    with open(new_issue_file, 'r') as yml:
        yml_issues = yaml.load(yml, Loader=yaml.FullLoader)

    return yml_issues

def parse_status_file(jira, filename, issues):
    """
    The main parsing function, which will decide what should go into the actual
    Jira call. This for example removes the beginning until it finds a
    standalone [ISSUE] tag. It will also remove all comments prefixed with '#'.
    """
    # Regexp to match Jira issue on a single line, i.e:
    # [Story]
    # [Epic]
    # ...
    regex = r'^\[Issue]\n$'

    # Regexp to mach a tag that indicates to stop processing completely:
    # [FIN]
    regex_fin = r'^\[FIN\]\n$'

    # Regexp to match for which project to use. This will remove Project: from the
    # match.
    regex_issue_type = r'(?:^Issue type:) *(.+)\n$'

    # Regexp to match for which summary to use. This will be used as epic name as well in case of epic. This woill remove Project: from the#
    # match:
    regex_summary = r'(?:^Summary:) *(.+)\n$'

    # Regexp to match for which project to use. This woill remove Project: from the#
    # match:
    regex_description = r'(?:^Description:) *(.+)\n$'

    # Regexp to match for which project to use. This woill remove Project: from the#
    # match:
    regex_project = r'(?:^Project:) *(.+)\n$'

    # Regexp to match for which project to use. This woill remove Project: from the#
    # match:
    regex_components = r'(?:^Components:) *(.+)\n$'

    # Regexp to match for which project to use. This woill remove Project: from the#
    # match:
    regex_assignee = r'(?:^Assignee:) *(.+)\n$'

    # Regexp to match for which project to use. This woill remove Project: from the#
    # match:
    regex_epic_link = r'(?:^Epic link:) *(.+)\n$'

    # Regexp to match for which project to use. This woill remove Project: from the#
    # match:
    regex_sprint = r'(?:^Sprint:) *(.+)\n$'

    # Regexp to match for which project to use. This woill remove Project: from the#
    # match:
    regex_original_estimate = r'(?:^Original estimate:) *(.+)\n$'

    # Regexp to match for a status update, this will remove 'Status' from the
    # match:
    regex_status = r'(?:^Status:) *(.+)\n$'

    # Contains the status text, it could be a file or a status email
    status = ""

    with open(filename) as f:
        status = f.readlines()

    myissue = "";

    # build list of {issue,comment} tuples found in status
    issue_comments = []
    for line in status:
        # New issue?
        match = re.match(regex, line)

        if match:

            myissue = match.group(1)
            validissue = True

            # if we ran a query, we might already have fetched the issue
            # let's try to find the issue there first, otherwise ask Jira
            try:
                issue = [x for x in issues if str(x) == myissue][0]
                issue_comments.append((issue, "", ""))

            # IndexError: we had fetched already, but issue is not found
            # TypeError: issues is None, we haven't queried Jira yet, at all
            except (IndexError, TypeError) as e:
                try:
                    issue = jira.issue(myissue)
                    issue_comments.append((issue, "", ""))
                except  Exception as e:
                    if 'Issue Does Not Exist' in e.text:
                        print('[{}] :  {}'.format(myissue, e.text))
                        validissue = False

        # Stop parsing entirely.  This needs to be placed before regex_stop
        # or the .* will match and [FIN] won't be processed
        elif re.search(regex_fin, line):
            break
        # If we have non-JIRA issue tags, stop parsing until we find a valid tag
        elif re.search(regex_stop, line):
                validissue = False
        elif transition and validissue:
            # If we have a match, then the new status should be first in the
            # group. Jira always expect the name of the state transitions to be
            # word capitalized, hence the call to the title() function. This
            # means that it doesn't matter if the user enter all lower case,
            # mixed or all upper case. All of them will work.
            new_status = transition.groups()[0].title()
            (i,c,_) = issue_comments[-1]
            issue_comments[-1] = (i, c, new_status)
        else:
            # Don't add lines with comments
            if (line[0] != "#" and issue_comments and validissue):
                (i,c,t) = issue_comments[-1]
                issue_comments[-1] = (i, c + line, t)

    issue_upload = []
    print("These JIRA cards will be updated as follows:\n")
    for (idx,t) in enumerate(issue_comments):
        (issue,comment,transition) = issue_comments[idx]

        # Strip beginning  and trailing blank lines
        comment = comment.strip('\n')

        # initialize here to avoid unassigned variables and useless code complexity
        resolution_id = transition_id = None
        resolution = transition_summary = ""

        if transition != "" and transition != str(issue.fields.status):
            # An optional 'resolution' attribute can be set when doing a transition
            # to Resolved, using the following pattern: Resolved / <resolution>
            if transition.startswith('Resolved') and '/' in transition:
                (transition, resolution) = map(str.strip, transition.split('/'))
                if not resolution in resolution_map:
                    print("Invalid resolution \"{}\" for issue {}".format(resolution, issue))
                    print("Possible resolution: {}".format([t for t in resolution_map]))
                    sys.exit(1)
                resolution_id = resolution_map[resolution]

            transition_map = dict([(t['name'].title(), t['id']) for t in jira.transitions(issue)])
            if not transition in transition_map:
                print("Invalid transition \"{}\" for issue {}".format(transition, issue))
                print("Possible transitions: {}".format([t for t in transition_map]))
                sys.exit(1)

            transition_id = transition_map[transition]
            if resolution:
                transition_summary = " %s => %s (%s)" % (issue.fields.status, transition, resolution)
            else:
                transition_summary = " %s => %s" % (issue.fields.status, transition)

        if comment == "" and not transition_id:
            log.debug("Issue [%s] has no comment or transitions, not updating the issue" % (issue))
            continue

        issue_upload.append((issue, comment,
                             {'transition': transition_id, 'resolution': resolution_id}))
        print("[%s]%s\n  %s" % (issue, transition_summary, "\n  ".join(comment.splitlines())))
    print("")

    issue_comments = issue_upload
    if issue_comments == [] or cfg.args.dry_run or should_update() == "n":
        if issue_comments == []:
            print("No change, Jira was not updated!\n")
        else:
            print("Comments will not be written to Jira!\n")
        if not cfg.args.s:
            print_status(status)
        sys.exit()

    # if we found something, let's update jira
    for (issue,comment,transition) in issue_comments:
        update_jira(jira, issue, comment, transition)

    print("Successfully updated your Jira tickets!\n")
    if not cfg.args.s:
        print_status(status)

def print_status_file(filename):
    with open(filename, 'r') as f:
        print(f.read())

################################################################################
# Yaml
################################################################################


def get_extra_comments():
    """ Read the jipdate config file and return all option comments. """
    try:
        yml_iter = cfg.yml_config['comments']
    except:
        # Probably no "comments" section in the yml-file.
        return "\n"

    return ("\n".join(yml_iter) + "\n") if yml_iter is not None else "\n"

def get_header():
    """ Read the jipdate config file and return all option header. """
    try:
        yml_iter = cfg.yml_config['header']
    except:
        # Probably no "comments" section in the yml-file.
        return ""

    return ("\n".join(yml_iter) + "\n\n") if yml_iter is not None else "\n"


def merge_issue_header():
    """ Read the configuration flag which decides if the issue and issue header
    shall be combined. """
    try:
        yml_iter = cfg.yml_config['use_combined_issue_header']
    except:
        # Probably no "use_combined_issue_header" section in the yml-file.
        return False
    return yml_iter


def get_header_separator():
    """ Read the separator from the jipdate config file. """
    try:
        yml_iter = cfg.yml_config['separator']
    except:
        # Probably no "separator" section in the yml-file.
        return " | "
    return yml_iter


def get_editor():
    """ Read the configuration flag that will decide whether to show the text
    editor by default or not. """
    try:
        yml_iter = cfg.yml_config['text-editor']
    except:
        # Probably no "text-editor" section in the yml-file.
        return True
    return yml_iter

def initialize_logger(args):
    LOG_FMT = ("[%(levelname)s] %(funcName)s():%(lineno)d   %(message)s")
    lvl = log.ERROR
    if args.v:
        lvl = log.DEBUG

    log.basicConfig(
        # filename="core.log",
        level=lvl,
        format=LOG_FMT,
        filemode='w')


################################################################################
# Main function
################################################################################
def main():
    argv = sys.argv
    parser = get_parser()

    # The parser arguments (cfg.args) are accessible everywhere after this call.
    cfg.args = parser.parse_args()

    initialize_logger(cfg.args)

    # This initiates the global yml configuration instance so it will be
    # accessible everywhere after this call.
    cfg.initiate_config()

    if not cfg.args.file:
        log.error("No file provided\n")
        parser.print_help()
        sys.exit(os.EX_USAGE)

    jira, username = jiralogin.get_jira_instance(False)

    if cfg.args.file is not None:
        filename = cfg.args.file
        issues = parse_issue_file(filename)
        print(issues)
        for issue in issues:
            # We should only find one project and one issue type otherwise something is wrong
            issue_meta_data = jira.createmeta(projectKeys=issue['Project'], issuetypeNames=issue['IssueType'], expand='projects.issuetypes.fields')
            issue_fields_dict = {}
            try:
                issue_fields_dict = issue_meta_data['projects'][0]['issuetypes'][0]['fields']
            except IndexError:
                print('Could not get meta data from Jira for project \"' + issue['Project'] + '\" and issue type \"' + issue['IssueType'] + '\"')

            if issue_fields_dict:
                fields = {
                    'project': {'key': issue['Project']},
                    'summary': issue['Summary'],
                    'description': issue['Description'],
                    'issuetype': {'name': issue['IssueType']},
                    'timetracking': {'originalEstimate': issue['OriginalEstimate']}
                }

                if 'AssigneeEmail' in issue.keys():
                    assignee = jira.search_assignable_users_for_issues(query=issue['AssigneeEmail'], project=issue['Project'])
                    # We assume that the first entry in the returned user array is the one we want
                    if len(assignee) > 0:
                        fields['assignee'] = {'id': assignee[0].accountId}

                if 'EpicLink' in issue.keys():
                    fields['customfield_10014'] = issue['EpicLink']

                if 'Component' in issue.keys():
                    components = jira.project_components(issue['Project'])
                    for c in components:
                        if c.name == issue['Component']:
                            fields['components'] = [{'id': str(c.id)}]

                sprint_found = True  # Only indicate sprint not found in case a sprint has been specified.
                if 'Sprint' in issue.keys():
                    sprint_found = False
                    boards_in_project = jira.boards(projectKeyOrID=issue['Project'])
                    for board in boards_in_project:
                        sprints_in_board = jira.sprints(board_id=board.id)
                        for sprint in sprints_in_board:
                            if sprint.name == issue['Sprint']:
                                fields['customfield_10020'] = sprint.id
                                print('Found '+ sprint.name + ' ' + str(sprint.id))
                                sprint_found = True

                if sprint_found:
                    print(fields)
                    new_issue = jira.create_issue(fields=fields)
                    print(new_issue)
                else:
                    print('Sprint \"' + issue['Sprint'] + '\" not found in project ' + issue['Project'])
    else:
        log.error("Trying to run script with unsupported configuration. Try using --help.")
        sys.exit(os.EX_USAGE)

if __name__ == "__main__":
    main()
