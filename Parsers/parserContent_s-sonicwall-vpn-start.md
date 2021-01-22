#### Parser Content
```Java
{
Name = s-sonicwall-vpn-start
  DataType = "vpn-start"
  Conditions = [ """msg="User login successful"""", "SSLVPN:" , "id=sslvpn"]
}
```