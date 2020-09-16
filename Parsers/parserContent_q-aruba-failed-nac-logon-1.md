#### Parser Content
```Java
{
Name = q-aruba-failed-nac-logon-1
  DataType = "nac-failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss-SS"
  Conditions = [ """ Failed Auth """, """Common.NAS-IP-Address=""" ]
  Fields = ${HPEParserTemplates.q-aruba-nac-logon.Fields} [
    """Common\.Request-Timestamp=({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d-\d+)"""
]
}
```