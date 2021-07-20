#### Parser Content
```Java
{
Name = cef-duo-VPN-login
  Product = Duo Access Security
  DataType ="vpn-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """ destinationServiceName=DUO ""","""VPN""", """SUCCESS""" ]
}
```