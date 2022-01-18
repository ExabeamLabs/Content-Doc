#### Parser Content
```Java
{
Name = s-checkpoint-firewall-block
  Conditions = [ """product=VPN-1 & FireWall-1""", """|i/f_name=""", """|action=block""" ]

s-checkpoint-firewall = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Splunk
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """"time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w-.]{1,2000})""",
    """\|orig=({host}[^\|]{1,2000})\|""",
    """\|i\/f_dir=({direction}[^\|]{1,2000})""",
    """\|service=({app_protocol}[^\|]{1,2000})\|""",
    """\|action=({action}[^\|]{1,2000})\|""",
    """\|app_rule_name=({rule}[^\|]{1,2000})\|""",
    """\|src=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^\|]{1,2000}))\|""",
    """\|s_port=({src_port}\d{1,100})""",
    """\|dst=(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\|]{1,2000}))\|""",
    """\|proto=({protocol}[^\|]{1,2000})\|""",
    """\|src_machine_name=({src_host}[^\|]{1,2000})""",
    """\|src_user_name=[^(]{1,2000}\(({user}[^)]{1,2000})""",
    """\|user=[^(]{1,2000}\(({user}[^)]{1,2000})"""
  
}
```