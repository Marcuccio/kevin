# Kevin
The program outputs a CSV file with the following columns:

- cveID: The CVE identifier
- kev: Whether the CVE is present in the Kevin feed (true or false)
- itw: Whether the CVE is present in the InTheWild feed (true or false)
- nuclei: Whether the CVE is present in the local Nuclei file (true or false)

## Sources
The inthewild and kevin sources are obtained from the following URLs: 

- inthewild: https://inthewild.io/api/exploited
- kevin: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Nuclei

## Usage

```rust
use kevin::run;

fn main() {
    let cves = vec![
		"CVE-2022-4262".to_owned(),
		"CVE-2022-42748".to_owned(),
		"CVE-2022-34047".to_owned(),
		"CVE-2022-32409".to_owned(),
		"CVE-2022-38553".to_owned(),
		"CVE-2022-31656".to_owned(),
		"CVE-2022-2548".to_owned(),
		"CVE-2022-41840".to_owned(),
		"CVE-2022-30514".to_owned(),
		"CVE-2022-0422".to_owned(),
		"CVE-2021-27104".to_owned(),
		"CVE-2022-36642".to_owned(),
		"CVE-2022-31268".to_owned(),
		"CVE-2022-0148".to_owned(),
		"CVE-2022-1057".to_owned()
    ];
    let report = run(&cves).unwrap();

    // Do something with the report...
}
````

```bash
[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
cveID,kev,itw,nuclei
CVE-2022-4262,true,true,false
CVE-2022-42748,false,false,true
CVE-2022-34047,false,false,true
CVE-2022-32409,false,false,true
CVE-2022-38553,false,false,true
CVE-2022-31656,false,false,true
CVE-2022-2548,false,false,false
CVE-2022-41840,false,false,true
CVE-2022-30514,false,false,true
CVE-2022-0422,false,false,true
CVE-2021-27104,true,true,false
CVE-2022-36642,false,false,true
CVE-2022-31268,false,false,true
CVE-2022-0148,false,false,true
CVE-2022-1057,false,false,true
```
