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
     """Host":\s{0,100}"({host}[^"]+)"""",
     """({time}\w{3}\s\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """IPProtocol":\s{0,100}({protocol}[^"]+),"""
     """ServerIP":\s{0,100}"({dest_ip}[^"]+)"""",
     """ConnectorPort":\s{0,100}({src_port}[^\s]+),""",
     """ServerPort":\s{0,100}({dest_port}[^\s]+),""",
     """Policy":\s{0,100}"\s{0,100}({policy}[^"]+)"""",
     """ConnectionStatus":\s{0,100}"({outcome}[^"]+)""""
     """"LogTimestamp":\s{0,100}"({time}[^"]+)""""
     """"SessionID":\s{0,100}"({session_id}[^"]+)""""
     """"ConnectionID":\s{0,100}"({connection_id}[^"]+)""""
     """"InternalReason":\s{0,100}"({reason}[^"]+)""""
     """"Username":\s{0,100}"(({user_email}[^"@]+?@[^"]+)|({user}[^"]+))""""
     """"ServicePort":\s{0,100}"({dest_port}[^"]+)""""
     """"ClientPublicIP":\s{0,100}"({src_ip}[^"]+)""""
     """"ClientCountryCode":\s{0,100}"({src_country}[^"]+)""""
     """"ClientZEN":\s{0,100}"({zen_code}[^"]+)""""
     """"Connector":\s{0,100}"(0|({host}[^"]+))""""
     """"ConnectorZEN":\s{0,100}"({zen_con_code}[^"]+)""""
     """"ConnectorIP":\s{0,100}"({host_ip}[^"]+)""""
     """"Host":\s{0,100}"({dest_host}[^"]+)""""
     """"Application":\s{0,100}"({app}[^"]+)""""
     """"AppGroup":\s{0,100}"({app_group}[^"]+)""""
     """"TimestampConnectionStart":\s{0,100}"({event_start_time}[^"]+)""""
     """"TimestampConnectionEnd":\s{0,100}"({event_stop_time}[^"]+)""""
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