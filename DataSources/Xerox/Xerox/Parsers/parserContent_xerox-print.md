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
    """id:\s{0,100}"{1,20}({printer_id}\d{1,100})"{1,20}\s{0,100}account_id""",
    """printed:\s{0,100}"{1,20}({time}[^"]{1,2000})"""",
    """printer_type:\s{0,100}"{1,20}({printer_type}\d{1,100})"{1,20}""",
    """printer_name:\s{0,100}"{1,20}({printer_name}[^"]{1,2000})"{1,20}""",
    """object_id:\s{0,100}"{1,20}({object_id}({object}\d{1,100}))"{1,20}""",
    """user_name:\s{0,100}"{1,20}(({domain}[^"\\]{1,2000})\\)?({user}[^"]{1,2000})"{1,20}""",
    """source_machine:\s{0,100}"{1,20}({src_host}[^"]{1,2000})"{1,20}""",
    """total_pages:\s{0,100}"{1,20}({num_pages}[^"]{1,2000})"{1,20}""",
    """ip_address:\s{0,100}"{1,20}0*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"{1,20}""",
    """department_name:\s{0,100}"{1,20}({department}[^"]{1,2000})"{1,20}""",
    """full_name:\s{0,100}"{1,20}({user_fullname}[^"]{1,2000})"{1,20}""",
    """document_title:\s{0,100}"{1,20}({document_name}({object}[^"]{1,2000}))"{1,20}"""
  ]
}
```