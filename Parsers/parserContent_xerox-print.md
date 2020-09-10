#### Parser Content
```Java
{
Name = xerox-print
  Vendor = Xerox
  Product= Xerox
  Lms = QRadar
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.s"
  Conditions = [ """account_id: ""","""printer_type: ""","""mono_duplex_count""","""color_duplex_count""" ]
  Fields = [
    """id:\s*"+({printer_id}\d+)"+\s*account_id""",
    """printed:\s*"+({time}[^"]+)"""",
    """printer_type:\s*"+({printer_type}\d+)"+""",
    """printer_name:\s*"+({printer_name}[^"]+)"+""",
    """object_id:\s*"+({object_id}({object}\d+))"+""",
    """user_name:\s*"+(({domain}[^"\\]+)\\)?({user}[^"]+)"+""",
    """source_machine:\s*"+({src_host}[^"]+)"+""",
    """total_pages:\s*"+({num_pages}[^"]+)"+""",
    """ip_address:\s*"+0*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"+""",
    """department_name:\s*"+({department}[^"]+)"+""",
    """full_name:\s*"+({user_fullname}[^"]+)"+""",
    """document_title:\s*"+({document_name}({object}[^"]+))"+"""
  ]
}
```