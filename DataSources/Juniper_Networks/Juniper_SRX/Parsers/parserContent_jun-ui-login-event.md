#### Parser Content
```Java
{
Name = jun-ui-login-event
    Vendor = Juniper Networks
    Product = Juniper SRX
    Lms = Direct
    DataType = "authentication-successful"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """UI_LOGIN_EVENT""" ]
    Fields = [
        """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)(?:z|Z)?""",
        """\s({host}[^\s]{0,2000})\s(\w+|-)\s(\d{1,100}|-)\sUI_LOGIN_EVENT""",
        """username="(?!N\/A)({user}[^"]{1,2000})"\s""",
        """ssh-connection="({src_ip}(\d{1,3}\.){3}\d{1,3})\s({src_port}\d{1,100})\s({dest_ip}(\d{1,3}\.){3}\d{1,3})\s({dest_port}\d{1,100})"\s""",
        """({event_name}UI_LOGIN_EVENT)"""
    ]
}
```