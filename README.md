# GTFObinScript
Automating GTFObin tests using Bash srcipts

This way you can easily run the GTFObin commands using just a bash script on a machine , helping tasks like SIEM detections or security tests on your desired detection profile.
All commands listed in [GTFObins](https://gtfobins.github.io/) are listed and used in this bash script.

- This script is tested on a fresh ubuntu lab environment, there are packages that can be installed using `requirements.sh` and some still remain which need snapp to install
- These packages installation may be different on other linux distros
- **It's recommended to use and run on a lab environment to avoid package conflicts , and high amount of packages to install**

> I'm working on this script to add more user interactions so easier to choose and run desired commands or categories

- 5-14-2025:
  - In current version there are only commands listed to run (no category selection options)
- 5-19-2025:
  - Some commands commented due to need of manual interaction or use of 'interrupt key' in the payload which caused whole script to stop
  - Added requirements.sh for installing some of packages required for the tests e.g apache,nano,metasploit...  
  
