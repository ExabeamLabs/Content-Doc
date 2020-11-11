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
        """\s({host}[^\s]*)\s(\w+|-)\s(\d+|-)\sUI_LOGIN_EVENT""",
        """username="(?!N\/A)({user}[^"]+)"\s""",
        """ssh-connection="({src_ip}(\d{1,3}\.){3}\d{1,3})\s({src_port}\d+)\s({dest_ip}(\d{1,3}\.){3}\d{1,3})\s({dest_port}\d+)"\s""",
        """({event_name}UI_LOGIN_EVENT)"""
    ]
}
```