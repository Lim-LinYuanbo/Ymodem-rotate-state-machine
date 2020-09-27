#include "series32f10x-uart.h"
#include "Ymodem.h"

#if 0
//发送
/*********************************************************************
 * @fn      ymodem_tx_set_fil : 自己随便实现的一个函数，用来设置待传送的文件
 * @param   fil_nm : 文件名
 */
uint8_t ymodem_tx_set_fil( char* fil_nm )           //此函数由[用户主动调用]，启动文件传输
{
    uint8_t ans = YMODEM_ERR;
    ans = YMODEM_OK;
    return ans;
}
/*********************************************************************
 * @fn      ymodem_tx_header : 系统调用，用来获取文件名和大小
 * @param   fil_nm : 文件名 fil_sz : 文件大小
 */
uint8_t ymodem_tx_header( char** fil_nm, unsigned long *fil_sz )
{
    uint8_t ans = YMODEM_ERR;
    ans = YMODEM_OK;
    return ans;
}
/*********************************************************************
 * @fn      ymodem_tx_finish : 当传输结束时，会被调用
 * @param   status : 关闭的原因 YMODEM_OK 或 YMODEM_ERR
 */
uint8_t ymodem_tx_finish( uint8_t status )                         //返回结束原因，成功还是出错
{
    return YMODEM_OK;
}
/*********************************************************************
 * @fn      ymodem_tx_pac_get : 调用此来读取文件中的相应数据
 * @param   buf : 待写入的缓冲区地址 offset : 数据的偏移 size : 数据的大小
 */
uint8_t ymodem_tx_pac_get( char *buf, unsigned long offset, unsigned long size )
{
    uint8_t ans = YMODEM_ERR;
    ans = YMODEM_OK;
    return ans;
}
#endif

int __putchar(const struct ym_port_ops *ops, char ch)
{
    return (ops->ym_port_ops_write)(ops->ym_port_desc, (uint8_t *)(&ch), sizeof(ch));
}
int __putbuf(const struct ym_port_ops *ops, char *buf, unsigned long len )
{
    return (ops->ym_port_ops_write)(ops->ym_port_desc, (uint8_t *)buf, len);
}

void ym_assert_handler(const char* ex_string, const char* func, unsigned long line)
{
    kprintf("assert:ex=[%s], func=[%s], line=[%d]\r\n", ex_string, func, line);
    __disable_irq();
    while (1);
}

