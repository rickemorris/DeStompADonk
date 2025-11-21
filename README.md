The following python scripts detect potential Timestomping activity in Linux and Windows operating systems respectively. These scripts create fake timestomping data for research purposes and a user can input their own directory as well.

To run, simply open a command prompt that allows python to be run.

Here is a view on an Ubuntu device:
remnux@remnux:~/ProjectTS$ python3 timestompcheckNix.py
Please enter an additional folder to analyze (or hit Enter to skip): personaldata
[+] Scanning user folder: personaldata

[+] Timestomp checking complete. 13640 files analyzed.
[+] Results can be found in timestomp_results_2025-11-19_22-46-20.csv


Here is the view on a Windows device:

PS C:\Users\vboxuser\Desktop > python .\timestompcheckWin.py
Please enter an additional folder to analyze (or hit Enter to skip):  public_html
[+] Creating test dataset...
[+] Dataset ready. Beginning analysis...
[+] Scanning user folder: public_html

[+] Timestomp checking complete. 13633 files analyzed.
[+] Results can be found in  timestomp_results_20251120_002941.csv

This script is useful for analysis in post-moretum scenarios for a quick turnaround time. 
