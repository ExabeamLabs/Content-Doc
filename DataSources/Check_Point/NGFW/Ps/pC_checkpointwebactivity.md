#### Parser Content
```Java
{
Name = checkpoint-web-activity
  Vendor = Check Point 
  Product = NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """CheckPoint""", """product:"URL Filtering"""", """ifname:"""" ]
  Fields = [
    """\Wtime:"({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wuser:"({user_lastname}[^,]{1,2000}),\s{0,100}({user_firstname}[\w\s]{1,2000}\S)\s{0,100}\(({account}.+?)\)""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst:"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Waction:"({action}[^"]{1,2000})""",
    """\Ws_port:"({src_port}\d{1,100})""",
    """\Wproto:"({protocol}[^"]{1,2000})""",
    """\Wservice:"({dest_port}\d{1,100})""",
    """\Wmatched_category:"({category}[^"]{1,2000})""",
    """\Wappi_name:"\s{0,100}({web_domain}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^;\/"]{1,2000})""",
    """\Wresource:"\s{0,100}(-|({full_url}[^"]{1,2000}))""",
    """\Wresource:"\s{0,100}(?:-|({protocol}[^:]{1,2000}))""",
    """\Wresource:"\s{0,100}(?:-|(\w+:\/+[^\/]{1,2000}\/({uri_path}[^?;"]{1,2000})))""",
    """\Wresource:"\s{0,100}(?:-|(\w+:\/+[^?]{1,2000}({uri_query}\?[^;"]{1,2000}?)))"""",
    """\Wweb_client_type:"(Other:)?\s{0,100}(?:-|({user_agent}[^"]{1,2000}))""",
    """\Worigin:"({origin_ip}[^"]{1,2000})""",
    """\Worigin_sic_name:"CN=({origin_name}[^",]{1,2000})""",
    """\Wproduct:"({product_name}[^"]{1,2000})""",
    """\Wsrc_machine_name:"({src_host}[^"@]{1,2000})@({domain}[^"]{1,2000})""",
    """\Wuser:"({user}[^"]{1,2000}?)\s{0,100}"""",
  ]
}
```