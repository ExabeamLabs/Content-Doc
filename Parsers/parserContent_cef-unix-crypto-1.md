#### Parser Content
```Java
{
Name = cef-unix-crypto-1
  DataType = "remore-logon"
  Conditions = [ """CEF""", """Unix|auditd""", """CRYPTO_SESSION""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\\|({outcome}[^\|]+)""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """spt=({src_port}\d+)""",
    """dpt=({dest_port}\d+)"""
    ]
}
```