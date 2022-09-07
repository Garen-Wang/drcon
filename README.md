# drcon

A simplified version of DrClient

## Usage

### Create Your Own `user-config.toml`

Create `user-config.toml` in root directory with your own info like the following:

```toml
username = "1234567890"
password = "123456"
hostname = "Dell-PC"
auth_ip = "114.114.114.114"
```

### Run Executable

If the network is connecting or connected, please send logoff at the beginning:

```bash
$ cargo run -- --iface <IFACE> --logoff
```

Then start the main program:

```bash
$ cargo run -- --iface <IFACE> 
```
