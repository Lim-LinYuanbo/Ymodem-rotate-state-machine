/**************************************************************************************************
 *                                            INCLUDES
 **************************************************************************************************/
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "Ymodem.h"

/*********************************************************************
 * CONSTANTS
 */
#define YMODEM_DATA_SIZE_128    128
#define YMODEM_DATA_SIZE_1024   1024

#define YMODEM_RX_IDLE          0
#define YMODEM_RX_ACK           1
#define YMODEM_RX_EOT           2
#define YMODEM_RX_ERR           3
#define YMODEM_RX_EXIT          4

#define YMODEM_TX_IDLE          0
#define YMODEM_TX_IDLE_ACK      1
#define YMODEM_TX_DATA          2
#define YMODEM_TX_DATA_ACK      3
#define YMODEM_TX_EOT           4
#define YMODEM_TX_ERR           5
#define YMODEM_TX_EXIT          6
/*********************************************************************
 * GLOBAL VARIABLES
 */
//static  uint8_t ym_rx_status = YMODEM_RX_IDLE;
//static  uint8_t ym_tx_status = YMODEM_RX_IDLE;
//static  unsigned long pac_size;
//static  unsigned long seek;
//static  unsigned long ym_tx_fil_sz;
//static  char  *ym_tx_pbuf;
//static  uint8_t ym_cyc;   //发送时的轮转变量

/*********************************************************************
 * EXTERNAL FUNCTIONS
 *********************************************************************/
extern void __putchar(const struct ym_port_ops *ops, char ch);
extern void __putbuf(const struct ym_port_ops *ops, char *buf, unsigned long len);
extern void ym_assert_handler(const char* ex_string, const char* func, unsigned long line);

/*********************************************************************
 * FUNCTIONS
 *********************************************************************/
#ifndef RT_ALIGN
#define RT_ALIGN(size, align)           (((size) + (align) - 1) & ~((align) - 1))
#endif
#ifndef YM_ASSERT
#define YM_ASSERT(EX) do {if (!(EX)) ym_assert_handler(#EX, __FUNCTION__, __LINE__);} while (0)
#endif

//核心函数
static unsigned short crc16(const unsigned char *buf, unsigned long count)
{
    unsigned short crc = 0;
    int i;

    while(count--)
    {
        crc = crc ^ *buf++ << 8;

        for (i=0; i<8; i++)
        {
            if (crc & 0x8000)
            {
                crc = crc << 1 ^ 0x1021;
            }
            else
            {
                crc = crc << 1;
            }
        }
    }
    return crc;
}

#if 0
static const char *u32_to_str(unsigned int val)
{
    /* Maximum number of decimal digits in u32 is 10 */
    static char num_str[11];
    int  pos = 10;
    num_str[10] = 0;

    if (val == 0)
    {
        /* If already zero then just return zero */
        return "0";
    }

    while ((val != 0) && (pos > 0))
    {
        num_str[--pos] = (val % 10) + '0';
        val /= 10;
    }

    return &num_str[pos];
}
#endif

static unsigned long str_to_u32(char* str)
{
    const char *s = str;
    unsigned long acc;
    int c;

    /* strip leading spaces if any */
    do
    {
        c = *s++;
    }
    while (c == ' ');

    for (acc = 0; (c >= '0') && (c <= '9'); c = *s++)
    {
        c -= '0';
        acc *= 10;
        acc += c;
    }
    return acc;
}
//返回包的类型
uint8_t ymodem_rx_pac_check(char* buf, unsigned long sz)
{
    char ch;
    ch = buf[0];
    if(sz < 128) //是个指令包
    {
        if(ch==EOT || ch==ACK || ch==NAK || ch==CAN || ch==CNC)
        {
            int i=1;
            while(i<sz && buf[i++]==ch);    //判断包中所有内容是否一样
            if(sz == i)     //是全部一样的话，则认为此命令包有效
                return ch;
            else
                return 0xff;
        }
        else
            return 0xff;      //错误的指令码
    }
    else
    {
        if(ch==SOH || ch==STX)
        {
            uint16_t crc1 = crc16((uint8_t*)(buf+PACKET_HEADER), sz-PACKET_OVERHEAD);
            uint16_t crc2 = ((uint16_t)(buf[sz-2]))*256+buf[sz-1];
            if(crc1 == crc2 && 0xff == (uint8_t)buf[1]+(uint8_t)buf[2])
                return ch;
            else
                return 0xff;      //数据包校验为错
        }
        else
            return 0xff;      //错误的指令码
    }
}
//**********************************************************************接收部分
static uint8_t ymodem_rx_pac_if_empty(char *buf, unsigned long sz)
{
    unsigned long offset=0;
    while(buf[offset]==0x00 && ++offset<sz);
    if(offset==sz)
        return true;
    else
        return false;
}
static uint8_t ymodem_rx_prepare(struct ym_core *handle, char *buf, unsigned long sz) //解析出头包中的文件名和大小
{
    uint8_t ans = YMODEM_OK;
    char *fil_nm;
    uint8_t   fil_nm_len;
    unsigned long fil_sz;
    fil_nm = buf;
    fil_nm_len = strlen(fil_nm);
    fil_sz = (unsigned long)str_to_u32(buf+fil_nm_len+1);
//    ans = ymodem_rx_header(fil_nm, fil_sz);
    if (handle->event->ym_event_header)
        ans = (handle->event->ym_event_header)(handle->event->ym_private_desc, fil_nm, fil_sz);
    return ans;
}
/*********************************************************************
 * @fn      ymodem_tx_put : Ymodem接收时，逻辑轮转调用函数
 * @param   buf : 数据缓冲区 buf : 数据大小
 */
int ymodem_rx_put(struct ym_core *handle, char *buf, unsigned long rx_sz)
{
    const struct ym_event_ops *event = handle->event;
    int ret = YMODEM_OK;
    if(0 == rx_sz)      //超时，从而得到的长度为0，则尝试发送“C”，并返回
    {
        __putchar(handle->port, 'C');
        return ret;
    }

    switch(handle->ym_rx_status)
    {
        case YMODEM_RX_IDLE:
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                case SOH:
                case STX:
                    handle->pac_size = (uint8_t)(buf[0])==SOH ? PACKET_SIZE:PACKET_1K_SIZE;
                    if(true == ymodem_rx_pac_if_empty(buf+PACKET_HEADER, handle->pac_size))   //判断是否是空包
                    {
                        __putchar(handle->port, ACK);
                        handle->ym_rx_status = YMODEM_RX_EXIT;
                        ret = YMODEM_PAC_EMPTY;
                        goto exit;                  //这是在本循环必须完成的操作，所以需要用到 goto 语句
                    }
                    else    //如果不是空包，则认为是第一个包（包含文件名和文件大小）
                    {
                        if(((handle->pac_size == PACKET_SIZE) || (handle->pac_size == PACKET_1K_SIZE))
                           && (YMODEM_PAC_HEADER == (ret = ymodem_rx_prepare(handle, buf+PACKET_HEADER, handle->pac_size))))
                        {
                            __putchar(handle->port, ACK);
                            handle->seek = 0;      //初始化变量，用于接收新文件
                            __putchar(handle->port, 'C');
                            handle->ym_rx_status = YMODEM_RX_ACK;
                        }
                        else
                        {
                            ret = YMODEM_ERR;
                            goto err; //在IDLE中接收到一个1024的数据包，则肯定是状态有问题
                        }
                    }
                    break;
                case EOT:
                    handle->ym_rx_status = YMODEM_RX_EXIT;
                    goto exit;                      //这是在本循环必须完成的操作，所以需要用到 goto 语句
                //break;
                default:
                    //__putchar(handle->port, NAK);      //不正常的状态，调试用
                    ret = YMODEM_ERR;
                    goto err;              //这儿暂时认为，包有误，就退出
                    //break;
            }
            break;
        case YMODEM_RX_ACK:                                         //1级——文件接收状态中
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                case SOH:
                case STX:
                    __putchar(handle->port, ACK);
                    handle->pac_size = (uint8_t)(buf[0])==SOH ? PACKET_SIZE:PACKET_1K_SIZE;
//                    ymodem_rx_pac_get(buf+PACKET_HEADER, handle->seek, handle->pac_size);  //将接收的包保存
                    if (event->ym_event_data)
                        (event->ym_event_data)(event->ym_private_desc, buf+PACKET_HEADER, handle->seek, handle->pac_size);
                    handle->seek += handle->pac_size;
                    //__putchar(handle->port, 'C');
                    ret = YMODEM_PAC_GET;
                    break;
                //指令包
                case EOT:
                    __putchar(handle->port, NAK);
                    handle->ym_rx_status = YMODEM_RX_EOT;
                    break;
                case CAN:
                    handle->ym_rx_status = YMODEM_RX_ERR;
                    ret = YMODEM_ERR;
                    goto err;
                //break;
                default:
                    __putchar(handle->port, NAK);      //不正常的状态，调试用
                    //goto err;           //这儿暂时认为，包有误，就重发
                    break;
            }
            break;
        case YMODEM_RX_EOT:         //在这里保存文件
        {
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                //指令包
                case EOT:
                    __putchar(handle->port, ACK);
//                    ymodem_rx_finish(YMODEM_OK);        //确认发送完毕，保存文件
                    if (event->ym_event_finish)
                        (event->ym_event_finish)(event->ym_private_desc, YMODEM_OK);
                    handle->ym_rx_status = YMODEM_RX_IDLE;
                    ret = YMODEM_PAC_EOT;
                    break;
                default:
                    goto err;
                    //break;
            }
        }
        break;
    err:
        case YMODEM_RX_ERR:         //在这里放弃保存文件,终止传输
            __putchar(handle->port, CAN);
//            ymodem_rx_finish(YMODEM_ERR);
            if (event->ym_event_finish)
                (event->ym_event_finish)(event->ym_private_desc, YMODEM_ERR);
            handle->ym_rx_status = YMODEM_RX_IDLE;
            ret = YMODEM_ERR;
            break;
        exit:
        case YMODEM_RX_EXIT:        //到这里，就收拾好，然后退出
            handle->ym_rx_status = YMODEM_RX_IDLE;
            //*这里还需要进行某些操作，使在退出后，不会再重新进入ymodem_rx_put()函数
            ret = YMODEM_PAC_EXIT;
            return ret;
        default:
            break;
    }

    return ret;
}
//**********************************************************************发送部分
#if 0
//pbuf 是指向缓冲区的最开始的地方， pac_sz 是数据区的大小
static uint8_t ymodem_tx_make_pac_data(struct ym_core *handle, char *pbuf, unsigned long pac_sz)
{
    uint8_t ans = YMODEM_ERR;
    uint16_t crc;

    pbuf[0] = pac_sz==128? SOH:STX;
    pbuf[1] = handle->ym_cyc;
    pbuf[2] = ~(handle->ym_cyc);
    crc = crc16((unsigned char const*)pbuf, pac_sz);
    pbuf[PACKET_HEADER+pac_sz]   = (uint8_t)(crc/256);
    pbuf[PACKET_HEADER+pac_sz+1] = (uint8_t)(crc&0x00ff);
    (handle->ym_cyc)++;
    return ans;
}
static uint8_t ymodem_tx_make_pac_header(struct ym_core *handle, char *pbuf, char *fil_nm, unsigned long fil_sz)
{
    uint8_t ans = YMODEM_ERR;
    uint8_t nm_len;
    memset(pbuf+PACKET_HEADER, 0, 128);
    if(fil_nm)
    {
        nm_len = strlen(fil_nm);
        strcpy(pbuf+PACKET_HEADER, fil_nm);
        strcpy(pbuf+PACKET_HEADER+nm_len+1, u32_to_str(fil_sz));
    }
    handle->ym_cyc = 0x00;
    ymodem_tx_make_pac_data(handle, pbuf, 128);
    return ans;
}
/*********************************************************************
 * @fn      ymodem_tx_put : Ymodem发送时，逻辑轮转调用函数
 * @param   buf : 数据缓冲区 buf : 数据大小
 * 说明：
 * 1.发送 [包  头] 状态：如果没有文件名，则发送空包，否则发送封装的头包
 * 2.发送 [数据包] 状态：发送数据包，出现问题或结束，则进入结束状态
 * 3.发送 [结  束] 状态：处理发送完成的相关事情
 */
void ymodem_tx_put(struct ym_core *handle, char *buf, unsigned long rx_sz)
{
    struct ym_event_ops *event = handle->event;
    char *fil_nm=NULL;
    unsigned long fil_sz=NULL;
    switch(handle->ym_tx_status)
    {
        case YMODEM_TX_IDLE:
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                case CNC:
                {
                    if(NULL == handle->ym_tx_pbuf)
                    {
                        handle->ym_tx_pbuf = malloc(RT_ALIGN(PACKET_OVERHEAD + PACKET_1K_SIZE, 4));
                        if(NULL == handle->ym_tx_pbuf)      //申请失败，则返回
                            break;
                    }
                    YM_ASSERT(event->ym_event_header != NULL);
                    if(YMODEM_OK == (event->ym_event_header)(event->ym_private_desc, (char *)(&fil_nm), (unsigned long)(&fil_sz)))   //得到 文件名和大小
                    {
                        //封装一个包头，然后发送出去
                        handle->ym_tx_fil_sz = fil_sz;
                        ymodem_tx_make_pac_header(handle, handle->ym_tx_pbuf, fil_nm, fil_sz);
                        __putbuf(handle->port->ym_port_desc, handle->ym_tx_pbuf, PACKET_OVERHEAD+PACKET_SIZE);
                        handle->ym_tx_status = YMODEM_TX_IDLE_ACK;
                    }
                    else //封装一个空包，然后发出去
                    {
                        ymodem_tx_make_pac_header(handle, handle->ym_tx_pbuf, NULL, NULL);
                        __putbuf(handle->port->ym_port_desc, handle->ym_tx_pbuf, PACKET_OVERHEAD+PACKET_SIZE);
                    }
                }
                break;
                case CAN:
                    handle->ym_rx_status = YMODEM_TX_ERR;
                    goto err_tx;
                //break;
                default:
                    goto err_tx;              //这儿暂时认为，包有误，就退出
                    //break;
            }
            break;
        case YMODEM_TX_IDLE_ACK:
        {
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                case ACK://准备发数据包
                    handle->ym_tx_status = YMODEM_TX_DATA;
                    break;
                case NAK://准备重发包头
                    handle->ym_tx_status = YMODEM_TX_IDLE;
                    break;
                default://啥也不做
                    break;
            }
        }
        break;
    dt_tx:
        case YMODEM_TX_DATA:                             //1级——文件发送状态中
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                case CNC:
                    YM_ASSERT(event->ym_event_data != NULL);
                    if(YMODEM_OK == (event->ym_event_data)(event->ym_private_desc, handle->ym_tx_pbuf+PACKET_HEADER, handle->seek, PACKET_1K_SIZE))  //读取下一组数据
                    {
                        if(YMODEM_OK == ymodem_tx_make_pac_data(handle, handle->ym_tx_pbuf, PACKET_1K_SIZE))
                        {
                            __putbuf(handle->port->ym_port_desc, handle->ym_tx_pbuf, PACKET_OVERHEAD+PACKET_1K_SIZE);
                            handle->ym_tx_status = YMODEM_TX_DATA_ACK;
                        }
                        else        //读取数据出错，结束传输
                        {
                            handle->ym_tx_status = YMODEM_TX_ERR;
                            goto err_tx;
                        }
                    }
                    break;
                case CAN:
                    handle->ym_rx_status = YMODEM_TX_ERR;
                    goto err_tx;
                //break;
                default:        //暂时啥也不做
                    break;
            }
            break;
        case YMODEM_TX_DATA_ACK:
        {
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                case ACK:
                    handle->seek += PACKET_1K_SIZE;
                    if(handle->seek < handle->ym_tx_fil_sz)     //数据未发送完（不能加‘=’！）
                        handle->ym_tx_status = YMODEM_TX_DATA_ACK;
                    else  //数据发送完
                    {
                        handle->ym_tx_status = YMODEM_TX_EOT;
                        __putchar(handle->port, EOT);
                    }
                    break;
                case CNC:       //如果接收方不先应答[ACK]而是直接发'C'在这里处理
                    handle->seek += PACKET_1K_SIZE;
                    if(handle->seek < handle->ym_tx_fil_sz)     //数据未发送完（不能加‘=’！）
                    {
                        handle->ym_tx_status = YMODEM_TX_DATA_ACK;
                        //下面的状态，因为我需要马上回复，所以用goto
                        goto dt_tx;         //发送下一个数据包
                    }
                    else  //数据发送完
                    {
                        handle->ym_tx_status = YMODEM_TX_EOT;
                        __putchar(handle->port, EOT);
                    }
                    break;
                default:
                    break;
            }
        }
        break;
        case YMODEM_TX_EOT:
        {
            switch(ymodem_rx_pac_check(buf, rx_sz))   //检查当前包是否合法,并返回包的类型
            {
                //指令包
                case NAK:
                    __putchar(handle->port, EOT);
                    break;
                case ACK:
                    __putchar(handle->port, ACK);
                    YM_ASSERT(event->ym_event_finish != NULL);
                    (event->ym_event_finish)(event->ym_private_desc, YMODEM_OK);
                    handle->ym_rx_status = YMODEM_TX_IDLE;
                    break;
                default:
                    break;
            }
        }
        break;
    err_tx:
        case YMODEM_TX_ERR:         //在这里放弃保存文件,终止传输
            __putchar(handle->port, CAN);
            YM_ASSERT(event->ym_event_finish != NULL);
            (event->ym_event_finish)(event->ym_private_desc, YMODEM_ERR);
        //break;                    //没有break，和下面公用代码
        case YMODEM_TX_EXIT:        //到这里，就收拾好，然后退出
            handle->ym_rx_status = YMODEM_RX_IDLE;
            //*这里还需要进行某些操作，使在退出后，不会再重新进入ymodem_rx_put()函数
            free(handle->ym_tx_pbuf);
            handle->ym_tx_pbuf = NULL;
            return;
        default:
            break;
    }
}
#endif


