#include <stdio.h>
#include <string.h>
#include "series32f10x-system.h"
#include "series32f10x-uart.h"
#include "ymodem.h"

static int port_write(void *fd, uint8_t *data, uint32_t len)
{
    struct uart_handle *p = (struct uart_handle *)fd;
    return rt_hw_usart_write(p, data, len);
}
static int port_read(void *fd, uint8_t *data, uint32_t len)
{
    struct uart_handle *p = (struct uart_handle *)fd;
    return rt_hw_usart_read(p, data, len);
}

struct ym_receive_file
{
    uint32_t total_size;
    uint32_t cur_size;
    char name[16];
};
static int file_header(void *private_data, char* fil_nm, unsigned long fil_sz)
{
    struct ym_receive_file *p = (struct ym_receive_file *)private_data;
    uint8_t ans = YMODEM_PAC_HEADER;

    if (fil_sz > 0)
    {
        strncpy(p->name, fil_nm, sizeof(p->name));
        p->total_size = fil_sz;
        kprintf("file_name=[%s], file_size=[%d], func=[%s]\r\n", fil_nm, fil_sz, __FUNCTION__);
    }

    return ans;
}
static int file_data(void *private_data, char *buf, unsigned long seek, unsigned long size)
{
    struct ym_receive_file *p = (struct ym_receive_file *)private_data;
    uint8_t ans = YMODEM_OK;

    p->cur_size += size;
    kprintf("seek=[%d], size=[%d], func=[%s]\r\n",seek, size, __FUNCTION__);

    return ans;
}
static int file_finish(void *private_data, uint8_t status)
{
    uint8_t ans = YMODEM_OK;

    kprintf("status=[%d], func=[%s]\r\n", status, __FUNCTION__);

    return ans;
}

int download_file(unsigned long addr)
{
#define YM_TIMEOUT_SEC  60
#define YM_SLEEP_MS     50
    extern struct uart_handle uart_2_handle;
    const struct ym_port_ops port_ops =
    {
        .ym_port_ops_init   = NULL,
        .ym_port_ops_deinit = NULL,
        .ym_port_ops_write  = port_write,
        .ym_port_ops_read   = port_read,
        .ym_port_desc       = &uart_2_handle,
    };
    struct ym_receive_file file_desc_instance = {0x0};
    const struct ym_event_ops ev_ops =
    {
        .ym_event_header = file_header,
        .ym_event_data   = file_data,
        .ym_event_finish = file_finish,
        .ym_private_desc = &file_desc_instance,
    };
    static struct ym_core ym;
    memset(&ym, 0, sizeof(ym));
    ym.port = &port_ops;
    ym.event = &ev_ops;

    int err = 0;
    int ym_state = 0;
    int ym_packet_num = 0;
    static uint8_t ym_recv_buf[1024+128] = {0x0};
    int sec_cnt = 0, ms_cnt=0;
    for (;;)
    {
        int ret = rt_hw_usart_read(&uart_2_handle, ym_recv_buf, sizeof(ym_recv_buf));
        if (ret)
        {
            int ym_ret = ymodem_rx_put(&ym, (char *)ym_recv_buf, ret);
            kprintf("ym_ret=[%d]\r\n", ym_ret);
            switch (ym_state)
            {
                case 0: // receive file name&ize
                    sec_cnt = 0;
                    if (YMODEM_PAC_HEADER == ym_ret)
                        ym_state = 1;
                    break;
                case 1: // receive file data||eof
                    sec_cnt = 55;
                    if (YMODEM_PAC_EOT == ym_ret)
                        ym_state = 2;
                    break;
                case 2: // receive last packet
                    if (YMODEM_PAC_HEADER == ym_ret)
                        ym_state = 3;
                    break;
                default:
                    kprintf("invalid case, ym_ret=[%d]\r\n", YMODEM_PAC_EMPTY);
                    break;
            }
            if (ym_state == 3)
                break;
            else
                continue;
        }

        if (ms_cnt >= (1000/YM_SLEEP_MS))
        {
            ms_cnt = 0;
            sec_cnt += 1;
            kprintf("sec_cnt=[%d]\r\n", sec_cnt);
            ymodem_rx_put(&ym, NULL, 0);
            if (sec_cnt >= YM_TIMEOUT_SEC)
            {
                err = 1;
                break;
            }
        }
        else
        {
            ms_cnt += 1;
            sys_delay_tick(sys_tick_from_ms(YM_SLEEP_MS));
        }
    }
    if (err)
        return -1;

    kprintf("ymodem receive success. ym_packet_num=[%d]\r\n", ym_packet_num);
    kprintf("file describe:name=[%s], total_size=[%d], cur_size=[%d]\r\n",
            file_desc_instance.name, file_desc_instance.total_size, file_desc_instance.cur_size);
    return 0;
}


