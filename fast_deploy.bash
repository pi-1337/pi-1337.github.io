
hugo build --baseURL=https://pi-1337.github.io/crypto-writeups/

cp -fr public/* build/
cd build/
git add .
git commit -m "$1"
git push

