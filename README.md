# Policy Checker Application

The **Policy Checker Application** analyzes network connections against pre-defined policies to determine if they are **CLEAN** or **SUSPICIOUS**. It processes network attack data and evaluates it based on IPs, ports, and protocols specified in a policy file.

## Features

* Reads and processes attack data from a CSV file.
* Evaluates attacks against policies defined in a JSON file.
* Supports caching for optimized IP, port, and protocol checks.
* Logs details about each attack evaluation a	nd performance statistics.
* Outputs suspicious connections to a separate CSV file for further investigation.

## Prerequisites

* Python 3.8 or higher

## Installation

Clone the repository:

```
git clone <repository-url>
cd <repository-folder>
```

## File Structure

* `app.py`: The main application script.
* `inputs/attacks.csv`: Input file containing attack data.
* `inputs/policy.json`: Input file containing policy rules.
* `suspicious_connections.csv`: Output file containing suspicious connections identified.
* `logs.log`: Log file generated during execution.

## Usage

1. Place the required input files in the `inputs` folder:

   * `attacks.csv`: Contains connection data to analyze.
   * `policy.json`: Defines the policies to evaluate attacks.
2. Run the application:

   ```
   python app.py
   ```

   * Add the `-d` flag to enable debug logging:
     ```
     python app.py -d DEBUG
     ```
3. The output will include:

   * A summary of **CLEAN** and **SUSPICIOUS** attacks in the terminal.
   * Detailed logs in the `logs.log` file.
   * Suspicious attacks saved to `suspicious_connections.csv`.

## Logging

Logs provide detailed information about:

* Evaluated attacks
* Policy matches
* Caching statistics
* Application performance

Logs are saved in `logs.log`.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Feel free to submit issues or contribute to the project by opening pull requests.

## Contact

For questions or feedback, please contact me.
