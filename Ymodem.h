#ifndef _M_YMODEM_H
#define _M_YMODEM_H
/**************************************************************************************************
 *                                            INCLUDES
 **************************************************************************************************/

#include <stdint.h>

/*********************************************************************
 * CONSTANTS
 */
#define PACKET_SEQNO_INDEX      (1)
#define PACKET_SEQNO_COMP_INDEX (2)

#define PACKET_HEADER           (3)     /* start, block, block-complement */
#define PACKET_TRAILER          (2)     /* CRC bytes */
#define PACKET_OVERHEAD         (PACKET_HEADER + PACKET_TRAILER)
#define PACKET_SIZE             (128)
#define PACKET_1K_SIZE          (1024)
#define PACKET_TIMEOUT          (1)

#define INITIAL

#define FILE_NAME_LENGTH (64)
#define FILE_SIZE_LENGTH (16)

#define YMODEM_OK               0
#define YMODEM_ERR              1       //校验包是否有问题，只能是“YMODEM_ERR==”而不应该“YMODEM_OK!=”
#define YMODEM_PAC_EMPTY        2       //包校验正确，但是里面是空值，在（IDLE状态，判断是否需要结束，退出）
#define YMODEM_PAC_HEADER       3
#define YMODEM_PAC_GET          4
#define YMODEM_PAC_EOT          5
#define YMODEM_PAC_EXIT         6
/* ASCII control codes: */
#define SOH (0x01)      /* start of 128-byte data packet */
#define STX (0x02)      /* start of 1024-byte data packet */
#define EOT (0x04)      /* end of transmission */
#define ACK (0x06)      /* receive OK */
#define NAK (0x15)      /* receiver error; retry */
#define CAN (0x18)      /* two of these in succession aborts transfer */
#define CNC (0x43)      /* character 'C' */

/* Number of consecutive receive errors before giving up: */
#define MAX_ERRORS    (5)

struct ym_port_ops
{
    void (*ym_port_ops_init)(void *);
    void (*ym_port_ops_deinit)(void *);
    int (*ym_port_ops_write)(void *, uint8_t *, uint32_t);
    int (*ym_port_ops_read)(void *, uint8_t *, uint32_t);

    void *ym_port_desc;
};
struct ym_event_ops
{
    int (*ym_event_header)(void *private_data, char* fil_nm, unsigned long fil_sz);
    int (*ym_event_data)(void *private_data, char *buf, unsigned long seek, unsigned long size);
    int (*ym_event_finish)(void *private_data, uint8_t status);

    void *ym_private_desc;
};
struct ym_core
{
    const struct ym_port_ops *port;
    const struct ym_event_ops *event;

    uint8_t ym_rx_status;
    uint8_t ym_tx_status;
    uint8_t ym_cyc;
    uint32_t pac_size;
    uint32_t seek;
    uint32_t ym_tx_fil_sz;
    char *ym_tx_pbuf;
};

/*********************************************************************
 * FUNCTIONS
 *********************************************************************/
//*注：接收——只有ymodem_rx_start()是接收到消息的时候调用，其它都是用户实现，ymodem自动调用
//*注：发送——用户调用ymodem_tx_header()只有ymodem_tx_start()是接收到消息的时候调用，其它都是用户实现，ymodem自动调用
int ymodem_rx_put(struct ym_core *handle, char *buf, unsigned long rx_sz);
#if 0
void ymodem_tx_put(struct ym_core *handle, char *buf, unsigned long rx_sz);
#endif

#endif    //_M_YMODEM_H


