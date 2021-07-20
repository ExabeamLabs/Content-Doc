#### Parser Content
```Java
{
Name = zscaler-activity
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = ["""InternalReason""" , """Client""", """IP""", """ConnectorZENSetupTime"""]
  Fields = [
     """Host":\s{0,100}"({host}[^"]{1,2000})"""",
     """({time}\w{3}\s\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """IPProtocol":\s{0,100}({protocol}[^"]{1,2000}),"""
     """ServerIP":\s{0,100}"({dest_ip}[^"]{1,2000})"""",
     """ConnectorPort":\s{0,100}({src_port}[^\s]{1,2000}),""",
     """ServerPort":\s{0,100}({dest_port}[^\s]{1,2000}),""",
     """Policy":\s{0,100}"\s{0,100}({policy}[^"]{1,2000})"""",
     """ConnectionStatus":\s{0,100}"({outcome}[^"]{1,2000})""""
     """"LogTimestamp":\s{0,100}"({time}[^"]{1,2000})""""
     """"SessionID":\s{0,100}"({session_id}[^"]{1,2000})""""
     """"ConnectionID":\s{0,100}"({connection_id}[^"]{1,2000})""""
     """"InternalReason":\s{0,100}"({reason}[^"]{1,2000})""""
     """"Username":\s{0,100}"(({user_email}[^"@]{1,2000}?@[^"]{1,2000})|({user}[^"]{1,2000}))""""
     """"ServicePort":\s{0,100}"({dest_port}[^"]{1,2000})""""
     """"ClientPublicIP":\s{0,100}"({src_ip}[^"]{1,2000})""""
     """"ClientCountryCode":\s{0,100}"({src_country}[^"]{1,2000})""""
     """"ClientZEN":\s{0,100}"({zen_code}[^"]{1,2000})""""
     """"Connector":\s{0,100}"(0|({host}[^"]{1,2000}))""""
     """"ConnectorZEN":\s{0,100}"({zen_con_code}[^"]{1,2000})""""
     """"ConnectorIP":\s{0,100}"({host_ip}[^"]{1,2000})""""
     """"Host":\s{0,100}"({dest_host}[^"]{1,2000})""""
     """"Application":\s{0,100}"({app}[^"]{1,2000})""""
     """"AppGroup":\s{0,100}"({app_group}[^"]{1,2000})""""
     """"TimestampConnectionStart":\s{0,100}"({event_start_time}[^"]{1,2000})""""
     """"TimestampConnectionEnd":\s{0,100}"({event_stop_time}[^"]{1,2000})""""
     """"ZENTotalBytesRxClient":\s{0,100}({rx_client_total_bytes}\d{1,100})"""
     """"ZENTotalBytesTxClient":\s{0,100}({tx_client_total_bytes}\d{1,100})"""
     """"ZENTotalBytesRxConnector":\s{0,100}({rx_connector_total_bytes}\d{1,100})"""
     """"ZENTotalBytesTxConnector":\s{0,100}({tx_connector_total_bytes}\d{1,100})"""
     """"PolicyProcessingTime":\s{0,100}({policy_runtime}\d{1,100})"""
     """"CAProcessingTime":\s{0,100}({ca_runtime}\d{1,100})"""
     """"AppLearnTime":\s{0,100}({app_learntime}\d{1,100})"""
     

  ]
  DupFields = ["outcome->conn_status", "app_group->activity_type", "rx_connector_total_bytes->bytes_in", "tx_connector_total_bytes->bytes_out"]
 
}
```