#### Parser Content
```Java
{
Name = s-brightmail-email
    Vendor = BrightMail
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """[Brightmail]""", """ A message from """, """ returned Disposition:""" ]
    Fields = [
      """\s({host}[\w\.-]+)\s+bmserver""",
      """A message from\s+<({sender}[^\s@]+@({external_domain_sender}[^\s@>]+))>?\s+source""",
      """source\s+<?({direction}\w+)+>?\s+to""",
      """to\s+<?({recipients}[^<>]+)>?\s+using""",
      """to\s+<?({recipient}[^\s@<]+@({external_domain_recipient}[^\s@>]+))>?\s+using""",
    ]
  }

  {
    Name = syslog-malwarebytes-security-alert
    Vendor = Malwarebytes
    Product = Malwarebytes Endpoint Protection
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """Malwarebytes-Endpoint-Security""","\"security_log\""]
    Fields = [
        """"+time"+\s*:\s*"+({time}.+?)"+\s*[,\]\}]""",
        """"+ip_address"+\s*:\s*"+({src_ip}.+?)"+\s*[,\]\}]""",
        """"+ip_address"+\s*:\s*"+({host}.+?)"+\s*[,\]\}]""",
        """"+host_name"+\s*:\s*"+({src_host}.+?)"+\s*[,\]\}]""",
        """"+host_name"+\s*:\s*"+({host}.+?)"+\s*[,\]\}]""",
        """"+domain"+\s*:\s*"+({domain}.+?)"+\s*[,\]\}]""",
        """"+logon_user"+\s*:\s*"+(({domain}[^\\]+)\\+)?({user}.+?)"+\s*[,\]\}]""",
        """"+threat_name"+\s*:\s*"+({alert_name}.+?)"+\s*[,\]\}]""",
        """"+object_type"+\s*:\s*"+({alert_type}.+?)"+\s*[,\]\}]""",
        """"+threat_level"+\s*:\s*"({alert_severity}.+?)"+\s*[,\]\}]""",
        """"+object"+\s*:\s*"+({malware_url}.+?)"+\s*[,\]\}]""",
        """"object":"({process}[^"]+\\({process_name}[^"]+))""", 
    ]
  }
```