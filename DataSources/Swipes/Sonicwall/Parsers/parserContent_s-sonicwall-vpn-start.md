#### Parser Content
```Java
{
Name = s-sonicwall-vpn-start
  Product = Sonicwall
  DataType = "vpn-start"
  Conditions = [ """msg="User login successful"""", "SSLVPN:" , "id=sslvpn"]
}
```