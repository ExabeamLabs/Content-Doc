#### Parser Content
```Java
{
Name = cef-unix-crypto-key-1
  DataType = "remote-logon"
  Conditions = [ """CEF""", """Unix|auditd""", """CRYPTO_KEY_USER""" ]
  Fields = ${UnixParserTemplates.cef-unix-template-1.Fields}[
    """CEF:([^\|]*\|){4}({event_name}[^|]+)\\"""
    ]
}
```