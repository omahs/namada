# 3) MANDATORY: Reset your validator node
- **You can skip to 3.1 if you don't need to reset the ledger state**
- This is the right time to save any logs file you want to share with us!
- Save your `pre-genesis` folder in the ledger base directory
    - `mkdir backup-pregenesis && cp -r .namada/pre-genesis backup-pregenesis/`
- Delete ledger base directory **(WARNING: THIS WILL ALSO DELETE YOUR VALIDATOR KEYS, DO NOT RUN UNLESS YOU'VE BACKED IT UP)**
    - `rm -rf .namada`

- Create an empty `.namada` folder
    - `mkdir .namada`
    - `mkdir .namada/pre-genesis`
- Copy the backuped file back to `.namada/pre-genesis` folder
    - `cp -r backup-pregenesis/* .namada/pre-genesis/`

```admonish note
Make sure to check the [Changelog](https://github.com/anoma/namada/tree/main/.changelog) and our other communication channels for any manual changes that may need to be made to the files in the pre-genesis folder.
```

## 3.1) Run your node as a genesis validator

- Wait for the genesis file to be ready, `CHAIN_ID`.
- Join the network with the `CHAIN_ID`
    ``` bash
    export CHAIN_ID="TBD"
    namada client utils join-network \
    --chain-id $CHAIN_ID --genesis-validator $ALIAS
    ```
- Start your node and sync
    - `NAMADA_TM_STDOUT=true namada node ledger run`
    - If you want more logs:
        - `NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run`
    -  If you want to save logs to a file:
        - `TIMESTAMP=$(date +%s)`
        - `NAMADA_LOG=debug NAMADA_TM_STDOUT=true namada node ledger run &> logs-${TIMESTAMP}.txt`
        - `tail -f -n 20 logs-${TIMESTAMP}.txt` (in another shell)
- If started correctly, you should see a the following log:
    - `[<timestamp>] This node is a validator ...`
    