$install_script = <<-EOF
wget -q https://github.com/containerd/nerdctl/releases/download/v0.17.1/nerdctl-full-0.17.1-linux-amd64.tar.gz
tar Cxzvvf /usr/local nerdctl-full-0.17.1-linux-amd64.tar.gz
sudo systemctl enable --now containerd
sudo systemctl enable --now buildkit
sudo apt-get update
sudo apt-get -qq install -y make
EOF

Vagrant.configure("2") do |config|
  config.vm.box = "debian/testing64"
  config.vm.provision "shell", inline: $install_script
  config.vm.synced_folder ".", "/vagrant", type: "rsync", rsync__exclude: ".git/"
end
