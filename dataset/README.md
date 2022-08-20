# Dataset & Evaluation Results

## 1. File Descriptions

* `MantisBT_versions.json`  lists the collected 145 versions in MantisBT.
* `Piwigo_versions.json`  lists the collected 154 versions in Piwigo.
* `cve.json` lists the collected 34 CVEs.  It contains the following elements:
   - `vuln_type` : the vulnerable type of the CVE.
   - `fixing_commits` : the given patch commits of this CVE.
* `ground_truth.json`  contains the labeling results on the 5,002 CVE-version pairs. Each result has the following elements:
    - `cve_id` : the CVE id.
    - `version` : the version name.
    - `is_affected` . It has 3 values: `affected` , `unaffected`, and `patched`.
    - `poc` : the PoC input that triggers the vulnerability on this `version`.
* `results/` is a folder that contains the results given by the evaluated tools: `afv.json`, `redebug.json`, `v0finder.json`, `vszz.json`, `vszz++.json`. Every file has the following elements:
    - `cve_id` : the CVE id.
    - `version` : the version name.
    - `is_affected`. It may have 3 values: 1 means affected, 0 means unaffected, and 2 means unknown (only AFV has this value).

## 2. Evaluation Results
The results in RQ1, RQ2, and RQ3 can be reproduced with the following commands.
```shell
$ pip3 install -r requirements.txt
$ python3 evaluate.py

Effectiveness Results of AFV. (RQ1)
1483    1034    35      449     0.9673  0.6972
3519    3218    45      301     0.9862  0.9145
5002    4252    80      750     0.9815  0.8501

Comparison Results with V-SZZ. (RQ2)
1034    35      449     0.9673  0.6972
962     1191    521     0.4468  0.6487
962     585     521     0.6218  0.6487

3218    45      301     0.9862  0.9145
2328    521     1191    0.8171  0.6616
2934    521     585     0.8492  0.8338

4252    80      750     0.9815  0.8501
3290    1712    1712    0.6577  0.6577
3896    1106    1106    0.7789  0.7789

Comparison Results with ReDebug and V0Finder in Identifying Affected Versions. (RQ2)
1034    35      449     0.9673  0.6972
871     146     612     0.8564  0.5873
239     20      1244    0.9228  0.1612
```