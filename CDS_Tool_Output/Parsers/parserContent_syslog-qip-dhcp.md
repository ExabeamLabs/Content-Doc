#### Parser Content
```Java
{
Name = syslog-qip-dhcp
    Vendor = Nokia VitalQIP
  Product = Nokia VitalQIP
    Lms = Syslog
    DataType = "dhcp"
    TimeFormat = "dd/MM/yyyy HH:mm:ss"
    Conditions = [ "QIP[-]: " ]
    Fields = [
      """QIP\[\-\]:([^,]*,){6}\s*({dest_ip}[a-fA-F\d.:]+)""",
      """QIP\[\-\]:([^,]*,){7}\s*({dest_host}[^,]*?)\s*,""",
      """QIP\[\-\]:([^,]*,){8}\s*({domain}([^,\s]+\s*?)+?)\s*,""",
      """QIP\[\-\]:([^,]*,){10}\s*({user}[^,]*?)\s*,""",
      """QIP\[\-\]:([^,]*,){11}\s*({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    ]
  }

 {
    Name = s-brightmail-email
    Vendor = Symantec
    Product = Symantec Brightmail
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