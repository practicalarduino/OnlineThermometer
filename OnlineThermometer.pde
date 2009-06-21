/**
 * OnlineThermometer
 *
 * Reads values from DS18B20 1-wire temperature sensors and displays
 * the current readings in a web page.
 *
 * Copyright 2009 Jonathan Oxer <jon@oxer.com.au>
 * http://www.practicalarduino.com/projects/easy/online-thermometer
 * Based on example code from the nuElectronics etherShield library
 */

// Requires the etherShield library for nuElectronics (and compatible)
// Ethernet shields. The latest version is available from the Practical
// Arduino site:
#include "etherShield.h"

// Modify the following two lines to suit your local network
// configuration. The MAC and IP address have to be unique on your LAN:
static uint8_t myMac[6] = {0x54,0x55,0x58,0x10,0x00,0x24};
static uint8_t myIp[4]  = {192,168,1,15};
static char baseurl[]   = "http://192.168.1.15/";
static uint16_t myPort = 80; // Listen port for tcp/www (range 1-254)

// Set up variables for the TCP/IP buffer
#define BUFFER_SIZE 500
static uint8_t buf[BUFFER_SIZE+1];
#define STR_BUFFER_SIZE 22
static char strbuf[STR_BUFFER_SIZE+1];

// Create an instance of the EtherShield object named "es"
EtherShield es=EtherShield();

// Prepare the webpage by writing the data to the TCP send buffer
uint16_t print_webpage(uint8_t *buf);
int8_t analyse_cmd(char *str);

// Specify data pins for connected DS18B20 temperature sensors
#define SENSOR_A  3
#define SENSOR_B  4
#define SENSOR_C  5
#define SENSOR_D  6
#define SENSOR_E  7
#define SENSOR_F  8


/**
 * Configure Ethernet shield
 */
void setup()
{
  /*initialize enc28j60*/
  es.ES_enc28j60Init(myMac);

  // Change clkout from 6.25MHz to 12.5MHz
  es.ES_enc28j60clkout(2);
  delay(10);

  /* Magjack leds configuration, see enc28j60 datasheet, page 11 */
  // LEDA=green LEDB=yellow

  // 0x880 is PHLCON LEDB=on, LEDA=on
  es.ES_enc28j60PhyWrite(PHLCON, 0x880);
  delay(500);

  // 0x990 is PHLCON LEDB=off, LEDA=off
  es.ES_enc28j60PhyWrite(PHLCON, 0x990);
  delay(500);

  // 0x880 is PHLCON LEDB=on, LEDA=on
  es.ES_enc28j60PhyWrite(PHLCON, 0x880);
  delay(500);

  // 0x990 is PHLCON LEDB=off, LEDA=off
  es.ES_enc28j60PhyWrite(PHLCON, 0x990);
  delay(500);

  // 0x476 is PHLCON LEDA=links status, LEDB=receive/transmit
  es.ES_enc28j60PhyWrite(PHLCON, 0x476);
  delay(100);

  //init the ethernet/ip layer:
  es.ES_init_ip_arp_udp_tcp(myMac, myIp, myPort);

  // Set up the data pins for communication with DS18B20 sensors
  digitalWrite(SENSOR_A, LOW);
  pinMode(SENSOR_A, INPUT);
  digitalWrite(SENSOR_B, LOW);
  pinMode(SENSOR_B, INPUT);
  digitalWrite(SENSOR_C, LOW);
  pinMode(SENSOR_C, INPUT);
  digitalWrite(SENSOR_D, LOW);
  pinMode(SENSOR_D, INPUT);
  digitalWrite(SENSOR_E, LOW);
  pinMode(SENSOR_E, INPUT);
  digitalWrite(SENSOR_F, LOW);
  pinMode(SENSOR_F, INPUT);
}


/**
 * Main program loop
 */
void loop(){
  uint16_t plen, dat_p;
  int8_t cmd;

  plen = es.ES_enc28j60PacketReceive(BUFFER_SIZE, buf);

  /*plen will ne unequal to zero if there is a valid packet (without crc error) */
  if(plen!=0) {

    // arp is broadcast if unknown but a host may also verify the mac address by sending it to a unicast address.
    if (es.ES_eth_type_is_arp_and_my_ip (buf,plen)) {
      es.ES_make_arp_answer_from_request (buf);
      return;
    }

    // check if ip packets are for us:
    if (es.ES_eth_type_is_ip_and_my_ip (buf,plen) == 0) {
      return;
    }

    if (buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V) {
      es.ES_make_echo_reply_from_request (buf,plen);
      return;
    }

    // tcp port www start, compare only the lower byte
    if (buf[IP_PROTO_P] == IP_PROTO_TCP_V && buf[TCP_DST_PORT_H_P] == 0 && buf[TCP_DST_PORT_L_P] == myPort) {
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V) {
        es.ES_make_tcp_synack_from_syn (buf); // make_tcp_synack_from_syn does already send the syn,ack
        return;
      }
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V) {
        es.ES_init_len_info (buf); // init some data structures
        dat_p = es.ES_get_tcp_data_pointer();
        if (dat_p==0) { // we can possibly have no data, just ack:
          if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V) {
            es.ES_make_tcp_ack_from_any (buf);
          }
          return;
        }
        if (strncmp ("GET ", (char *) & (buf[dat_p]), 4) != 0) {
          // head, post and other methods for possible status codes see:
          // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
          plen = es.ES_fill_tcp_data_p (buf,0,PSTR ("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>200 OK</h1>"));
          goto SENDTCP;
        }
        if (strncmp("/ ", (char *) & (buf[dat_p+4]), 2) == 0){
          plen = print_webpage (buf);
          goto SENDTCP;
        }
        cmd = analyse_cmd ((char *) & (buf[dat_p+5]));
        if (cmd == 1){
          plen = print_webpage (buf);
        }
        if (cmd == 2){
          plen = print_webpage_about (buf);
        }
SENDTCP:  es.ES_make_tcp_ack_from_any(buf); // send ack for http get
          es.ES_make_tcp_ack_with_data(buf,plen); // send data
      }
    }
  }
}

// The returned value is stored in the global var strbuf
uint8_t find_key_val (char *str,char *key)
{
  uint8_t found = 0;
  uint8_t i = 0;
  char *kp;
  kp = key;
  while (*str &&  *str!=' ' && found==0) {
    if (*str == *kp) {
      kp++;
      if (*kp == '\0') {
        str++;
        kp=key;
        if (*str == '=') {
          found = 1;
        }
      }
    } else {
      kp = key;
    }
    str++;
  }
  if (found == 1) {
    // copy the value to a buffer and terminate it with '\0'
    while (*str &&  *str!=' ' && *str!='&' && i<STR_BUFFER_SIZE) {
      strbuf[i]=*str;
      i++;
      str++;
    }
    strbuf[i]='\0';
  }
  return(found);
}

/**
 * Process HTTP request to find value of 'cmd' parameter
 */
int8_t analyse_cmd (char *str)
{
  int8_t r = -1;

  if (find_key_val (str,"cmd")) {
    if (*strbuf < 0x3a && *strbuf > 0x2f) {
      // is a ASCII number, return it
      r = (*strbuf-0x30);
    }
  }
  return r;
}

/**
 * Read temperature sensors and create web page to return to client
 */
uint16_t print_webpage (uint8_t *buf)
{
  // Arrays to hold the temperature reading from each sensor
  char temp_string_a[10];
  char temp_string_b[10];
  char temp_string_c[10];
  char temp_string_d[10];
  char temp_string_e[10];
  char temp_string_f[10];

  int i;                 // Counter used while iterating over reading arrays
  uint16_t plen;         // Length of response packet

  // Read all the temperature sensors
  getCurrentTemp(SENSOR_A, temp_string_a);
  getCurrentTemp(SENSOR_B, temp_string_b);
  getCurrentTemp(SENSOR_C, temp_string_c);
  getCurrentTemp(SENSOR_D, temp_string_d);
  getCurrentTemp(SENSOR_E, temp_string_e);
  getCurrentTemp(SENSOR_F, temp_string_f);

  // Send HTTP content-type header
  plen = es.ES_fill_tcp_data_p (buf, 0, PSTR ("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"));

  // Read sensor A
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("Sensor A:"));
  i=0;
  while (temp_string_a[i]) {
    buf[TCP_CHECKSUM_L_P+3+plen]=temp_string_a[i++];
    plen++;
  }
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<br />"));
  
  // Read sensor B
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("Sensor B:"));
  i=0;
  while (temp_string_b[i]) {
    buf[TCP_CHECKSUM_L_P+3+plen]=temp_string_b[i++];
    plen++;
  }
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<br />"));
  
  // Read sensor C
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("Sensor C:"));
  i=0;
  while (temp_string_c[i]) {
    buf[TCP_CHECKSUM_L_P+3+plen]=temp_string_c[i++];
    plen++;
  }
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<br />"));
  
  // Read sensor D
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("Sensor D:"));
  i=0;
  while (temp_string_d[i]) {
    buf[TCP_CHECKSUM_L_P+3+plen]=temp_string_d[i++];
    plen++;
  }
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<br />"));
  
  // Read sensor E
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("Sensor E:"));
  i=0;
  while (temp_string_e[i]) {
    buf[TCP_CHECKSUM_L_P+3+plen]=temp_string_e[i++];
    plen++;
  }
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<br />"));
  
  // Read sensor F
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("Sensor F:"));
  i=0;
  while (temp_string_f[i]) {
    buf[TCP_CHECKSUM_L_P+3+plen]=temp_string_f[i++];
    plen++;
  }
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<br />"));

  // Display a form button to update the display
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<form METHOD=get action=\""));
  plen = es.ES_fill_tcp_data (buf, plen, baseurl);
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=hidden name=cmd value=1>"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=submit value=\"Data\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("</form>"));
  
  // Display a form button to access the "about" page
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<form METHOD=get action=\""));
  plen = es.ES_fill_tcp_data (buf, plen, baseurl);
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=hidden name=cmd value=2>"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=submit value=\"About\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("</form>"));
  
  return (plen);
}

/**
 * Generate a web page containing the "About" text
 */
uint16_t print_webpage_about (uint8_t *buf)
{
  uint16_t plen;         // Length of response packet

  // Send HTTP content-type header
  plen = es.ES_fill_tcp_data_p (buf, 0, PSTR ("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"));

  // Display the text for the "About" page
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<h1>Online Thermometer v1.0</h1>"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("As featured in Practical Arduino.<br />"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("See <a href=\"http://practicalarduino.com\">practicalarduino.com</a> for more info."));

  // Display a form button to update the display
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<form METHOD=get action=\""));
  plen = es.ES_fill_tcp_data (buf, plen, baseurl);
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=hidden name=cmd value=1>"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=submit value=\"Data\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("</form>"));
  
  // Display a form button to access the "about" page
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("<form METHOD=get action=\""));
  plen = es.ES_fill_tcp_data (buf, plen, baseurl);
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR ("\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=hidden name=cmd value=2>"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("<input type=submit value=\"About\">"));
  plen = es.ES_fill_tcp_data_p (buf, plen, PSTR("</form>"));
  
  return (plen);
}


/**
 */
void OneWireReset (int Pin) // reset.  Should improve to act as a presence pulse
{
  digitalWrite(Pin, LOW);
  pinMode(Pin, OUTPUT);        // bring low for 500 us
  delayMicroseconds(500);
  pinMode(Pin, INPUT);
  delayMicroseconds(500);
}

/**
 */
void OneWireOutByte(int Pin, byte d) // output byte d (least sig bit first).
{
  byte n;

  for (n=8; n!=0; n--)
  {
    if ((d & 0x01) == 1)  // test least sig bit
    {
      digitalWrite(Pin, LOW);
      pinMode(Pin, OUTPUT);
      delayMicroseconds(5);
      pinMode(Pin, INPUT);
      delayMicroseconds(60);
    }
    else
    {
      digitalWrite(Pin, LOW);
      pinMode(Pin, OUTPUT);
      delayMicroseconds(60);
      pinMode(Pin, INPUT);
    }

    d = d>>1; // now the next bit is in the least sig bit position.
  }
}

/**
 */
byte OneWireInByte(int Pin) // read byte, least sig byte first
{
  byte d, n, b;

  for (n=0; n<8; n++)
  {
    digitalWrite (Pin, LOW);
    pinMode (Pin, OUTPUT);
    delayMicroseconds (5);
    pinMode (Pin, INPUT);
    delayMicroseconds (5);
    b = digitalRead (Pin);
    delayMicroseconds (50);
    d = (d >> 1) | (b<<7); // shift d to right and insert b in most sig bit position
  }
  return (d);
}

/**
 * Read temperature from a DS18B20.
 * int sensorPin: Arduino digital I/O pin connected to sensor
 * char *temp: global array to be populated with current reading
 */
void getCurrentTemp (int sensorPin, char *temp)
{
  int HighByte, LowByte, TReading, Tc_100, sign, whole, fract;

  OneWireReset (sensorPin);
  OneWireOutByte (sensorPin, 0xcc);
  OneWireOutByte (sensorPin, 0x44); // Perform temperature conversion, strong pullup for one sec

  OneWireReset (sensorPin);
  OneWireOutByte (sensorPin, 0xcc);
  OneWireOutByte (sensorPin, 0xbe);

  LowByte = OneWireInByte (sensorPin);
  HighByte = OneWireInByte (sensorPin);
  TReading = (HighByte << 8) + LowByte;
  sign = TReading & 0x8000;  // test most sig bit
  if (sign) // negative
  {
    TReading = (TReading ^ 0xffff) + 1; // 2's complement
  }
  Tc_100 = (6 * TReading) + TReading / 4;    // multiply by (100 * 0.0625) or 6.25

  whole = Tc_100 / 100;  // separate off the whole and fractional portions
  fract = Tc_100 % 100;

  if (sign) {
    temp[0] = '-';
  } else {
    temp[0] = '+';
  }

  if (whole/100 == 0) {
    temp[1] = ' ';
  } else {
    temp[1] = whole/100+'0';
  }

  temp[2] = (whole-(whole/100)*100)/10 +'0' ;
  temp[3] = whole-(whole/10)*10 +'0';
  temp[4] = '.';
  temp[5] = fract/10 +'0';
  temp[6] = fract-(fract/10)*10 +'0';
  temp[7] = '\0';
}
