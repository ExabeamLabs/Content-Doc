#### Parser Content
```Java
{
Name = radius-nac-logon
    Vendor = Radius
    Product = Radius
    Lms = Direct
    DataType = "nac-logon"
    TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
    Conditions = [ """RADIUS Session Logs""", """RADIUS.Acct-Framed-IP-Address=""", """Common.Host-MAC-Address=""" ]
    Fields = [
      """exabeam_raw=\d{2}: \d{2}:\d{2

}
```