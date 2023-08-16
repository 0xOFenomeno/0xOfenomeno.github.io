---
title: Hack The Box - Forensics - TrueSecrets
published: true
---

# [](#Introduction)Introduction
**TrueSecrets** is an "Easy" forensics challenge on HackTheBox. I thought that it will be a bit tougher to resolve it, nevertheless it was very important to read completely the description to identify this challenge's context.

# [](#Description)Challenge Description
```
Our cybercrime unit has been investigating a well-known APT group for several months. 
The group has been responsible for several high-profile attacks on corporate organizations.
However, what is interesting about that case, is that they have developed a custom command & control server of their own. 
Fortunately, our unit was able to raid the home of the leader of the APT group and take a memory capture of his computer while it was still powered on. 
Analyze the capture to try to find the source code of the server.
```

So the main point was to find the source code of the custom C2 server located on the cybercriminal's computer.


My work environment for resolving this challenge:
- Windows 11
- WSL2 with Ubuntu 20.04 LTS
- An [Exegol](https://github.com/ThePorgs/Exegol) instance installed on WSL2


# [](#Analysis)Memory analysis

For the memory analysis (TrueSecrets.raw, the only file provided for this challenge), I used Volatility2 installed on Exegol (Volatility3 is also available). Firstly I identified the OS profile with **imageinfo** command. Little tip: always redirect the output into a text file in order to avoid time loss.

```
volatility2 -f TrueSecrets.raw imageinfo > imageinfo.txt
```

The profile was **Win7SP1x86_23418**.

After that, I decided to analyze processes with **pstree**, network connexions with **netscan**, try to find minjected code with **malfind**  but I remembered that the aim of this challenge was to find the **source code** of the custom C2 server located on the cybercriminal's computer..yes life is easier when you start thinking...


So... to find the source code file, Volatility's **filescan** command is your friend.

```
volatility2 -f TrueSecrets.raw --profile=Win7SP1x86_23418 filescan > filescan.txt
```


After a simple analysis of the filescan output, I found interesting things related to the **IEUser** under usual directories: Desktop, Downloads and Documents.

```
cat filescan.txt | grep 'Users\\IEUser\\D.*'
```
![](/assets/truesecrets/grep_output.png)

Despite the presence of the ***DumpIt.exe*** file, the context of the challenge directed me to ***development.tc*** and ***backup_development.zip***.

Due to file permissions, I wasn't able to dump ***developement.tc***, however I was able to dump ***backup_development.zip***.


```
volatility2 -f TrueSecrets.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000000bbf6158 --name backup_developement -D /workspace/htb/chall/forensics/truesecrets/filedump
```

After dumping the zip file, I extracted its content... and...
![](/assets/truesecrets/zip_extraction.png)

The TrueCrypt volume was retrieved, but what about the related passphrase? If you check the Volatility cheatsheet, you can see that it's possible to extract the passphrase with **truecryptpassphrase** command.

![](/assets/truesecrets/passphrase.png)



# [](#Truecrypt)Truecrypt...


So we have the truecrypt volume and its passphrase, but how to mount that?

Thanks to this [link](https://www.toptip.ca/2021/01/linux-mounting-truecrypt-volume-with.html), I successfully mounted the Truecrypt volume with cryptsetup.

```
sudo cryptsetup --type tcrypt open /path/to/truecrypt-volume mapping-name
sudo mount -o uid=1001 /dev/mapper/mapping-name /media/tcv
```


After mouting the trucrypt volume under ***/media/tsecrets*** I started to analyze its content.

![](/assets/truesecrets/truecrypt_content.png)

***AgentServer.cs*** I was nearly sure that it was the source code of the custom C2 server...and I was right.

```cs
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

class AgentServer {

    static void Main(String[] args)
    {
        var localPort = 40001;
        IPAddress localAddress = IPAddress.Any;
        TcpListener listener = new TcpListener(localAddress, localPort);
        listener.Start();
        Console.WriteLine("Waiting for remote connection from remote agents (infected machines)...");

        TcpClient client = listener.AcceptTcpClient();
        Console.WriteLine("Received remote connection");
        NetworkStream cStream = client.GetStream();

        string sessionID = Guid.NewGuid().ToString();

        while (true)
        {
            string cmd = Console.ReadLine();
            byte[] cmdBytes = Encoding.UTF8.GetBytes(cmd);
            cStream.Write(cmdBytes, 0, cmdBytes.Length);

            byte[] buffer = new byte[client.ReceiveBufferSize];
            int bytesRead = cStream.Read(buffer, 0, client.ReceiveBufferSize);
            string cmdOut = Encoding.ASCII.GetString(buffer, 0, bytesRead);

            string sessionFile = sessionID + ".log.enc";
            File.AppendAllText(@"sessions\" + sessionFile,
                Encrypt(
                    "Cmd: " + cmd + Environment.NewLine + cmdOut
                ) + Environment.NewLine
            );
        }
    }

    private static string Encrypt(string pt)
    {
        string key = "AKaPdSgV";
        string iv = "QeThWmYq";
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
        byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(pt);

        using (DESCryptoServiceProvider dsp = new DESCryptoServiceProvider())
        {
            var mstr = new MemoryStream();
            var crystr = new CryptoStream(mstr, dsp.CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write);
            crystr.Write(inputBytes, 0, inputBytes.Length);
            crystr.FlushFinalBlock();
            return Convert.ToBase64String(mstr.ToArray());
        }
    }
}

```
So understanding the **AgentServer.cs** file, it encrypts command executions on victims' computers into session files with DES ciphering and encodes it with Base64. 

Under the session ***malware_agent/sessions/*** I found  3 encrypted log files generated by the code above:

- 5818acbe-68f1-4176-a2f2-8c6bcb99f9fa.log.enc 
- c65939ad-5d17-43d5-9c3a-29c6a7c31a32.log.enc 
- de008160-66e4-4d51-8264-21cbc27661fc.log.enc



I wrote the **Decrypt** function to decrypt log files content, but intuitively, I directly chose to decrypt the last line of the last file (i.e ***de008160-66e4-4d51-8264-21cbc27661fc.log.enc***) because I felt that the flag was here (no joke). 

```
+iTzBxkIgVWgWm/oyP/Uf6+qW+A+kMTQkouTEammirkz2efek8yfrP5l+mtFS+bWA7TCjJDK2nLAdTKssL7CrHnVW8fMvc6mJR4Ismbs/d/fMDXQeiGXCA==
```

```cs
private static string Decrypt(string ct)
{
    string key = "AKaPdSgV";
    string iv = "QeThWmYq";
    byte[] keyBytes = Encoding.UTF8.GetBytes(key);
    byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
    byte[] inputBytes = Convert.FromBase64String(ct);

    using (DESCryptoServiceProvider dsp = new DESCryptoServiceProvider())
    {
        var mstr = new MemoryStream();
        var crystr = new CryptoStream(mstr, dsp.CreateDecryptor(keyBytes, ivBytes), CryptoStreamMode.Write);
        crystr.Write(inputBytes, 0, inputBytes.Length);
        crystr.FlushFinalBlock();
        return Encoding.UTF8.GetString(mstr.ToArray());
    }
}
```


And here is the flag...


![](/assets/truesecrets/flag.png)


# Conclusion

This was an easy one. If you have any questions or feedback on this writeup, or if you simply want talk about cybersecurity you can DM me on Twitter [@o_fenomen0](https://twitter.com/o_fenomen0) or on Discord **@0xofenomeno**.










