# YARA

* Description: identifying specific files by looking at the characteristics of a large number of files to see if any of them match the profile
* Installation
  * On Linux: download tar file from <https://github.com/virustotal/yara/releases/tag/v4.0.2>
  * Install dependencies: `sudo apt-get install automake libtool make gcc pkg-config`
  * Install YARA: `tar -zxf yara-4.0.2.tar.gz` -> `cd yara-4.0.2/` -> `./bootstrap.sh`
  * Compile YARA: `./configure` -> `make` -> `sudo make install`
  * Confirm Installation: `sudo make install`
* Usage
  * Write YARA Rules: <https://yara.readthedocs.io/en/stable/writingrules.html>
  * Run rule file against a target: `yara [OPTIONS] RULES_FILE TARGET`
  * YARA Flags
    * -m: Prints the associated meta information to the terminal after a YARA scan.
    * -s: Prints the matching strings to the terminal after a YARA scan.
    * -r: Recursively scan all subfolders within the target location to ensure everything is scanned.
  * YarGen to automatically generate rules for files: <https://github.com/Neo23x0/yarGen/releases>
    * Installation
      * `YarGen: tar -zxf yarGen-0.18.0.tar.gz`
      * `sudo apt-get install python-pip`
      * `sudo pip install pefile cd`
      * `sudo pip install scandir lxml naiveBayesClassifier`
      * `python yarGen.py --update`
      * `python yarGen.py --help`
    * Usage
      * `python yarGen.py -m /root/Desktop/Malware -o ./TestRule.yara`
      * `python yarGen.py`: Runs the yarGen python script
      * `-m /root/Desktop/Malware`: Create rules for files inside the Malware folder
      * `-o ./TestRule.yara`: Output the generated rule to the current folder
      * `cat TestRule.yara`: read rules
* Resources:
  * <https://yara.readthedocs.io/en/stable/gettingstarted.html>
  * <https://yara.readthedocs.io/en/stable/writingrules.html>
  * <https://yara.readthedocs.io/en/stable/commandline.html>
  * <https://github.com/Yara-Rules/rules>
