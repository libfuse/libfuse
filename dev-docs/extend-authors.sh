#!/bin/bash

# Check if a starting tag is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <starting_tag>"
    echo "Example: $0 fuse-3.16.2"
    exit 1
fi

START_TAG=$1

# Extract email addresses from git log
git_emails=$(git log ${START_TAG}..HEAD --format='<%aE>' | sort -u | sed 's/^<//;s/>$//')

# Extract email addresses from AUTHORS file
authors_emails=$(grep -oP '(?<=<)[^>]+' AUTHORS | sort -u)

# Find new email addresses (in git_emails but not in authors_emails)
# -1 suppresses lines unique to AUTHORS, -3 suppresses lines common to both
# Result: only lines unique to git_emails (i.e., new authors)
new_emails=$(comm -1 -3 <(echo "$authors_emails") <(echo "$git_emails"))

# If there are new email addresses, add corresponding authors to the AUTHORS file
if [ -n "$new_emails" ]; then
    echo -e "\nNew authors to be added:"
    echo -e "\n# New authors since ${START_TAG}" >> AUTHORS
    for email in $new_emails; do
        author=$(git log -1 --format='%aN <%aE>' --author="$email")
        echo "$author"
        echo "$author" >> AUTHORS
    done
    echo "AUTHORS file has been updated."
else
    echo "No new authors found since ${START_TAG}."
fi
