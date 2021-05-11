#### Parser Content
```Java
{
Name = syslog-mcafee-dlp-email-alert
      Vendor = McAfee
      Product = McAfee DLP
      Lms = Direct
      DataType = "dlp-email-alert"
      TimeFormat = "MM/dd/yyyy HH:mm:ss a"
      Conditions = [ """<McAfee DLP Conditions>""" ]
      Fields = [
        """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
        """([^\|]*\|){0}"?({alert_id}\d{1,100})(\||")""",
        """(".*?"\||[^|]*\|){1}"({subject}[^"]+)"\|""",
        """(".*?"\||[^|]*\|){4}"?({alert_name}[^"]+)(\||")""",
        """(".*?"\||[^|]*\|){4}"?({alert_type}[^"]+)(\||")""",
        """(".*?"\||[^|]*\|){1}"({alert_type}[^"]+)"\|\d{1,100}\|\d{1,100}\|"WEB""",
        """(".*?"\||[^|]*\|){5}"?({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (AM|am|PM|pm))""",
        """(".*?"\||[^|]*\|){8}"?({sender}[^"]+)(\||")""",
        """(".*?"\||[^|]*\|){10}"({recipients}[^"]+)"""",
        """(".*?"\||[^|]*\|){10}"({target}[^"]+)"""",
        """(".*?"\||[^|]*\|){10}"'?({external_address}[^@]+@[^'",]+)""",
        """(".*?"\||[^|]*\|){10}"'?[^@]+@({external_domain}[^'",]+)""",
        """(".*?"\||[^|]*\|){6}"?({alert_severity}\d{1,100})(\||")""",
        """(".*?"\||[^|]*\|){11}"?({domain}[^"\\\/]+)?[\\\/]*({user}[^"\\\/]+)(\||")"""
      ]
      DupFields = [ "sender->email_user" ]
    }
```