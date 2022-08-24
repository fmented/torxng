# torxng
1 script to deploy [searxng](https://github.com/searxng/searxng) on tor network

```bash
git clone https://github.com/fmented/torxng.git
sudo chmod +x torxng/main.sh
sudo torxng/main.sh
```

## what torxng do behind the scene
- updating system
- installing necessary packages 
- setting up [searxng-docker](https://github.com/searxng/searxng-docker)
- setting up tor
