# Kevin
KEVIN is a powerful tool designed to empower your understanding of Common Vulnerabilities and Exposures (CVEs). With KEVIN, you can effortlessly prioritize CVE data, making informed decisions to enhance your cybersecurity measures. It retrieves valuable information from multiple sources:

- [inthewild](https://inthewild.io/api/exploited)
- [kevin](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [Nuclei](https://github.com/projectdiscovery/nuclei-templates)

You can use this tool to easily verify wether some of your CVEs are marked as dangerous!

Kevin outputs a CSV file with the following columns:

- cveID: The CVE identifier
- kev: Whether the CVE is present in the CISA-KEV feed (true or false)
- itw: Whether the CVE is present in the InTheWild feed (true or false)
- nuclei: Whether the CVE is present in the local Nuclei file (true or false)

## How to use it

```bash
cat ./example/cves.txt | kevin
[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
cveID,kev,itw,nuclei
CVE-2022-42748,false,false,false
CVE-2022-0148,false,false,false
CVE-2022-31656,false,false,false
CVE-2022-34047,false,false,false
CVE-2022-30514,false,false,false
CVE-2021-27104,true,true,false
CVE-2022-41840,false,false,false
CVE-2022-38553,false,false,false
CVE-2022-36642,false,false,false
CVE-2022-32409,false,false,false
CVE-2022-1057,false,false,false
CVE-2022-2548,false,false,false
CVE-2022-4262,true,true,false
CVE-2022-0422,false,false,false
CVE-2022-31268,false,false,false
```

## ... or use kevin in your projects

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
