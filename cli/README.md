### MSP CLI 
A zero-dependency interactive shell that transforms the Firewalla MSP API into a familiar Cisco-style Command Line Interface. It demonstrates how to manage session contexts (Box GIDs), filter devices by box, and toggle security rules using a stateful navigation flow.

### Quick Start

Assume you've already cloned `https://github.com/firewalla/msp-api-examples.git` and `cd msp-api-examples`

```bash
cd interactive-cisco-style-cli
domain="<YOUR-MSP-DOMAIN>" token="<YOUR-MSP-TOKEN>" node ./index.js
```

### Dependencies
- [Node.js](https://nodejs.org/)
- Zero-Dependency: Does not require npm, pnpm, or any external packages.
