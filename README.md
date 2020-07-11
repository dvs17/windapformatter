# windapformatter
Credits to https://github.com/ropnop/windapsearch/

Analyses the output from windapsearch and extracts/converts useful information for pentest/redteams assessments

## Example Usage
python3.8 windapformatter.py -r allinfo -f

```
usage: wind-formatter.py [-h] [-f] [-spn] [-pnr] [-pne] [-prf] [-tfd] [-admin] [-r READ]

Extracts windapsearch output into a pretty format

optional arguments:
  -h, --help            show this help message and exit
  -f, --full            Get All Info
  -spn, --serviceprinciplename
                        List SPN Users
  -pnr, --passwordnotrequire
                        Lists Enabled accounts with Password Not required
  -pne, --passwordneverexpire
                        Lists Enabled accounts with Password Never Expire
  -prf, --passwordreversibleformat
                        List Account where Passwords stored in Reversible Format
  -tfd, --trustedfordelegation
                        Lists Accounts Trusted for Delegation
  -admin, --admin       Lists Admin accounts
  -r READ, --read READ  Read output from windapsearch
```
