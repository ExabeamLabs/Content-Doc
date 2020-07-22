#### Parser Content
```Java
{
Name = bro-ftp-1
  DataType = "app-activity"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"command":""", """"user""", """"reply_code""" ]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"user":\s*"({user}[^"]+)""",
    """"password":\s*"({password}[^"]+)""",
    """"command":\s*"({activity}[^"]+)""",
    """"reply_code":\s*({trans_id}\d+)""",
    """"reply_msg":\s*"({additional_info}[^"]+)""",
    """"data_channel\.resp_p":\s*({dest_port}\d+)""",
  ]
}
```