#include "stm32wrapper.h"

//24 MHz
const struct rcc_clock_scale benchmarkclock = {
  .pllm = 8, //VCOin = HSE / PLLM = 1 MHz
  .plln = 192, //VCOout = VCOin * PLLN = 192 MHz
  .pllp = 8, //PLLCLK = VCOout / PLLP = 24 MHz (low to have 0WS)
  .pllq = 4, //PLL48CLK = VCOout / PLLQ = 48 MHz (required for USB, RNG)
  .pllr = 0,
  .hpre = RCC_CFGR_HPRE_DIV_NONE,
  .ppre1 = RCC_CFGR_PPRE_DIV_2,
  .ppre2 = RCC_CFGR_PPRE_DIV_NONE,
  .pll_source = RCC_CFGR_PLLSRC_HSE_CLK,
  .voltage_scale = PWR_SCALE1,
  .flash_config = FLASH_ACR_DCEN | FLASH_ACR_ICEN | FLASH_ACR_LATENCY_0WS,
  .ahb_frequency = 24000000,
  .apb1_frequency = 12000000,
  .apb2_frequency = 24000000,
};

void clock_setup(void)
{
    rcc_clock_setup_pll(&benchmarkclock);
    rcc_periph_clock_enable(RCC_RNG);
    rcc_periph_clock_enable(RCC_GPIOD);
    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_USART2);
    rcc_periph_clock_enable(RCC_DMA1);
    rng_enable();

    flash_prefetch_enable();
}

void gpio_setup(void)
{
    /* Setup GPIO pin GPIO12 on GPIO port D for LED. */
    gpio_mode_setup(GPIOD, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO12);

    /* Setup GPIO pins for USART2 transmit. */
    gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO2);

    /* Setup GPIO pins for USART2 receive. */
    gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO3);

    /* Setup USART2 TX and RX pin as alternate function. */
    gpio_set_af(GPIOA, GPIO_AF7, GPIO3);
    gpio_set_af(GPIOA, GPIO_AF7, GPIO2);

}

void usart_setup(int baud)
{
    /* Setup USART2 parameters. */
    usart_set_baudrate(USART2, baud);
    usart_set_databits(USART2, 8);
    usart_set_stopbits(USART2, USART_STOPBITS_1);
    usart_set_mode(USART2, USART_MODE_TX_RX);
    usart_set_parity(USART2, USART_PARITY_NONE);
    usart_set_flow_control(USART2, USART_FLOWCONTROL_NONE);

    /* Finally enable the USART. */
    usart_enable(USART2);
}

void flash_setup(void)
{
    FLASH_ACR |= (1 << 9);
    FLASH_ACR |= (1 << 10);
    FLASH_ACR |= FLASH_ACR_PRFTEN;
}

void send_USART_str(const char* in)
{
    int i;
    for(i = 0; in[i] != 0; i++) {
        gpio_toggle(GPIOD, GPIO12); /* LED on/off */
        usart_send_blocking(USART2, (unsigned char)in[i]);
        gpio_toggle(GPIOD, GPIO12); /* LED on/off */
    }
    usart_send_blocking(USART2, '\r');
    usart_send_blocking(USART2, '\n');
}

void send_USART_bytes(const unsigned char* in, int n)
{
    int i;
    for(i = 0; i < n; i++) {
        gpio_toggle(GPIOD, GPIO12); /* LED on/off */
        usart_send_blocking(USART2, in[i]);
        gpio_toggle(GPIOD, GPIO12); /* LED on/off */
    }
}

void recv_USART_bytes(unsigned char* out, int n)
{
    int i;
    for(i = 0; i < n; i++) {
        gpio_toggle(GPIOD, GPIO12); /* LED on/off */
        out[i] = usart_recv_blocking(USART2);
        gpio_toggle(GPIOD, GPIO12); /* LED on/off */
    }
}
