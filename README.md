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
- 