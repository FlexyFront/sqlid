# SQLID

**SQLiD** is a simple Node.js middleware designed to detect and block potential SQL injection attempts. It uses regular expressions and an LRU (Least Recently Used) caching mechanism to temporarily restrict access from suspicious users.

## Features

- Detects common SQL injection patterns in user input
- Temporarily blocks access for repeated suspicious attempts using an LRU cache
- Customizable SQL injection patterns for advanced use cases
- Easy integration with Express.js applications

## Installation

This is a [Node.js](https://nodejs.org/en/) module available through the
[npm registry](https://www.npmjs.com/). Installation is done using the
[`npm install` command](https://docs.npmjs.com/getting-started/installing-npm-packages-locally):

You can install this package via npm:

```bash
npm install sqlid 
```
## Usage 

For JavaScript projects

```js
import { sqlid } from sqlid;
// Rest of the code
// Data must be parsed
app.use(sqlid);

```

## LRU Cache

The LRU cache is configured to block repeated suspicious attempts from the same IP address for a limited time.

Maximum Cache Items: 1000
Time to Live (TTL): 5 minutes

These settings can be adjusted in the LRU cache configuration:

```bash
const attackCache = new LRUCache({
  max: 1000,
  ttl: 1000 * 60 * 60 // 1-hour block for persistent offenders
});
```

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

