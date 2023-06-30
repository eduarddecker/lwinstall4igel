# Installation of lacework datacollector on a igel machine
# wget https://github.com/fabnord/lw/raw/main/Archive.zip
# unzip Archive.zip
# cd data

set -e

cp -r ./data/* /

./control/postinst

echo '{"Tokens": {"Accesstoken": "a9b69b5695b948f97c17172f366953031a3e24dffd0aef321bf5f164"}, "serverurl": "https://api.lacework.net" }' > /var/lib/lacework/config/config.json

service datacollector restart