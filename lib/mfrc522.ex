defmodule MFRC522 do
  use Bitwise
  use GenServer

  alias ElixirALE.GPIO
  alias ElixirALE.SPI

  require Logger

  @mfrc_default_spi "spidev0.0"
  @mfrc_default_spi_frequency 10_000_000
  @mfrc_default_ss_pin 24
  @mfrc_default_reset_pin 25

  @max_len 16
  @pcd_idle 0x00
  @pcd_authent 0x0E
  #@pcd_receive 0x08
  #@pcd_transmit 0x04
  @pcd_transceive 0x0C
  @pcd_reset_phase 0x0F
  #@pcd_calc_crc 0x03

  @picc_req_idl 0x26
  #@picc_req_all 0x52
  @picc_anti_coll 0x93
  #@picc_select_tag 0x93
  #@picc_authent_1a 0x60
  #@picc_authent_1b 0x61
  #@picc_read 0x30
  #@picc_write 0xA0
  #@picc_decrement 0xC0
  #@picc_increment 0xC1
  #@picc_restore 0xC2
  #@picc_transfer 0xB0
  #@picc_halt 0x50

  @mi_ok 0
  #@mi_not_ag_err 1
  @mi_err 2

  @command_reg 0x01
  @comm_ien_reg 0x02
  #@div_len_reg 0x03
  @comm_irq_reg 0x04
  #@div_irq_reg 0x05
  @error_reg 0x06
  #@status_1_reg 0x07
  #@status_2_reg 0x08
  @fifo_data_reg 0x09
  @fifo_level_reg 0x0A
  #@water_level_reg 0x0B
  @control_reg 0x0C
  @bit_framing_reg 0x0D
  #@coll_reg 0x0E

  @mode_reg 0x11
  #@tx_mode_reg 0x12
  #@rx_mode_reg 0x13
  @tx_control_reg 0x14
  @tx_auto_reg 0x15
  #@tx_sel_reg 0x16
  #@rx_sel_reg 0x17
  #@rx_threshold_reg 0x18
  #@demod_reg 0x19

  #@mifare_reg 0x1C

  #@serial_speed_reg 0x1F

  
  #@crc_result_reg_m 0x21
  #@crc_result_reg_l 0x22
  
  #@mod_width_reg 0x24
  
  #@rf_cfg_reg 0x26
  #@gs_n_reg 0x27
  #@cw_gs_p_reg 0x28
  #@mod_gs_p_reg 0x29
  @t_mode_reg 0x2A
  @t_prescaler_reg 0x2B
  @t_reload_reg_h 0x2C
  @t_reload_reg_l 0x2D
  #@t_counter_value_reg_h 0x2E
  #@t_counter_value_reg_l 0x2F

  #@test_sel_1_reg 0x31
  #@test_sel_2_reg 0x32
  #@test_pin_en_reg 0x33
  #@test_pin_value_reg 0x34
  #@test_bus_reg 0x35
  #@auto_test_reg 0x36
  #@version_reg 0x37
  #@analog_test_reg 0x38
  #@test_dac_1_reg 0x39
  #@test_dac_2_reg 0x3A
  #@test_adc_reg 0x3B


  def start_link(config \\ []) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  def init(config) do
    pin_ss = Keyword.get(config, :ss, @mfrc_default_ss_pin)
    pin_reset = Keyword.get(config, :rst, @mfrc_default_reset_pin)
    device = Keyword.get(config, :spi, @mfrc_default_spi)
    speed_hz = Keyword.get(config, :spi_speed, @mfrc_default_spi_frequency)

    {:ok, ss} = GPIO.start_link(pin_ss, :output)
    {:ok, rst} = GPIO.start_link(pin_reset, :output)
    {:ok, spi} = SPI.start_link(device, speed_hz: speed_hz, mode: 0)

    GPIO.write(ss, 1)
    GPIO.write(rst, 1)
    
    {:ok,
     %{
       spi: %{pid: spi, ss: ss},
       rst: rst,
       config: %{hard_reset: false},
       parent: [],
       progress: false
     }}
  end

  def mode(:reader), do: GenServer.call(__MODULE__, {:initialize, :reader})

  def handle_info(:reader, state) do
    verification(state[:spi], @picc_req_idl)
    reader_worker(state)
    {:noreply, state}
  end

  def handle_call({:initialize, :reader}, from, state) do
    {pid, _ref} = from
    initialize_(state)
    reader_worker(state)
    {:reply, :ok, %{state | :parent => pid}}
  end

  def handle_cast(:read_mifare, state) do
    GenServer.cast(__MODULE__, {:read_progress, true})
    {:ok, uid} = anticoll(state[:spi])
    [bit_xor | uid_] = uid |> Enum.reverse()

    if (xor_list(uid_) == bit_xor), do: send(state.parent, {:mfrc522, uid_})
    {:noreply, state}
  end

  def handle_cast({:read_progress, value}, state) do
    {:noreply, %{state | :progress => value}}
  end

  defp verification(spi, req_mode) do
    case request(spi, req_mode) do
      {:ok, _bits} -> GenServer.cast(__MODULE__, :read_mifare)
      {:error, _err} -> nil
      _ -> nil
    end
  end

  defp xor_list(list) do
    if (length(list) >= 2) do
      {ini, fim} = list |> Enum.split(2)
      xor_list([Enum.at(ini, 0) ^^^ Enum.at(ini, 1)] ++ fim)
    else
      Enum.at(list, 0)
    end
  end
  defp reader_worker(state) do
    unless state.progress, do: Process.send_after(__MODULE__, :reader, 100)
  end

  defp initialize_(state) do
    GPIO.write(state[:rst], 1)

    reset(state[:spi])

    write_register(state[:spi], @t_mode_reg, 0x8D)
    write_register(state[:spi], @t_prescaler_reg, 0x3E)
    write_register(state[:spi], @t_reload_reg_l, 30)
    write_register(state[:spi], @t_reload_reg_h, 0)

    write_register(state[:spi], @tx_auto_reg, 0x40)
    write_register(state[:spi], @mode_reg, 0x3D)

    antenna_on(state[:spi])
  end

  defp request(spi, req_mode) do
    write_register(spi, @bit_framing_reg, 0x07)
    {status, _back_data, back_bits} = to_card(spi, @pcd_transceive, [req_mode])

    if status != @mi_ok or back_bits != 0x10 do
      {:error, @mi_err}
    else
      {:ok, back_bits}
    end
  end

  defp anticoll(spi) do
    write_register(spi, @bit_framing_reg, 0x00)

    {status, back_data, _back_bits} = to_card(spi, @pcd_transceive, [@picc_anti_coll, 0x20])

    if status == @mi_ok do
      if length(back_data) == 5 do
        num_check = ser_num_check(back_data)
        if num_check != Enum.at(back_data, length(back_data) - 1) do 
          GenServer.cast(__MODULE__, {:read_progress, false})
          {:error, @mi_err}
        end
      else
        Logger.error("Length -> #{length(back_data)}")
        GenServer.cast(__MODULE__, {:read_progress, false})
        {:error, @mi_err}
      end
      GenServer.cast(__MODULE__, {:read_progress, false})
      {:ok, back_data}
    else
      Logger.error("to_card")
      GenServer.cast(__MODULE__, {:read_progress, false})
      {:erro, status}
    end
  end

  defp ser_num_check(data, num \\ 0, i \\ 0) do
    if i < length(data) do
      ser_num_check(data, num ^^^ Enum.at(data, i), i + 1)
    else
      num
    end
  end
  defp to_card(spi, command, send_data) do
    case command do
      @pcd_authent ->
        irq_en = 0x12
        write_register(spi, @comm_ien_reg, irq_en ||| 0x80)

      @pcd_transceive ->
        irq_en = 0x77
        write_register(spi, @comm_ien_reg, irq_en ||| 0x80)

      _ ->
        irq_en = 0x00
        write_register(spi, @comm_ien_reg, irq_en ||| 0x80)
    end

    clear_bit_mask(spi, @comm_irq_reg, 0x80)
    set_bit_mask(spi, @fifo_level_reg, 0x80)

    write_register(spi, @command_reg, @pcd_idle)

    if is_list(send_data),
      do: Enum.map(send_data, fn x -> write_register(spi, @fifo_data_reg, x) end),
      else: write_register(spi, @fifo_data_reg, send_data)

    write_register(spi, @command_reg, command)

    if command == @pcd_transceive, do: set_bit_mask(spi, @bit_framing_reg, 0x80)

    case command do
      @pcd_authent ->
        wait_irq = 0x10
        irq_resp(spi, irq?(spi, wait_irq), command)

      @pcd_transceive ->
        wait_irq = 0x30
        irq_resp(spi, irq?(spi, wait_irq), command)
        

      _ ->
        wait_irq = 0x00
        irq_resp(spi, irq?(spi, wait_irq), command)
    end
  end

  defp irq_resp(spi, resp_irq, command) do
    if resp_irq != 0 do
      if (read_register(spi, @error_reg) &&& 0x1B) == 0x0 do
        if command == @pcd_transceive do
          n_fifo_ = read_register(spi, @fifo_level_reg)
          last_bits = read_register(spi, @control_reg) &&& 0x07

          if last_bits != 0 do
            {@mi_ok, n_fifo(spi, n_fifo_), (n_fifo_ - 1) * 8 + last_bits}
          else
            {@mi_ok, n_fifo(spi, n_fifo_), n_fifo_ * 8}
          end
        end
      else
        {@mi_err, [], 0}
      end
    else
      {@mi_err, [], 0}
    end
  end

  defp n_fifo(spi, fifo) do
    cond do
      fifo == 0 -> [read_register(spi, @fifo_data_reg)]
      fifo > @max_len -> for _i <- 0..(@max_len - 1), do: [] ++ read_register(spi, @fifo_data_reg)
      fifo -> for _i <- 0..(fifo - 1), do: [] ++ read_register(spi, @fifo_data_reg)
    end
  end

  defp irq?(spi, wait_irq, i \\ 2000) do
      n = read_register(spi, @comm_irq_reg)
      c1 = if (n &&& 0x01) != 0 , do: true, else: false
      c2 = if (n &&& wait_irq) != 0 , do: true, else: false
      
      if ((i != 0) and c1 and c2) do 
       irq?(spi, wait_irq, (i - 1)) 
      else
        i
      end
  end

  defp reset(spi) do
    write_register(spi, @command_reg, @pcd_reset_phase)
  end

  defp antenna_on(spi) do
    value = read_register(spi, @tx_control_reg)
    if (bnot(value &&& 0x03) != 0) do
      set_bit_mask(spi, @tx_control_reg, 0x03)
    end
  end

  defp antenna_off(spi) do
    clear_bit_mask(spi, @tx_control_reg, 0x03)
  end

  defp set_bit_mask(spi, address, mask) do
    write_register(spi, address, read_register(spi, address) ||| mask)
  end

  defp clear_bit_mask(spi, address, mask) do
    write_register(spi, address, read_register(spi, address) &&& bnot(mask))
  end

  ########### SPI INTERFACE ##################
  defp write_register(spi, address, value) do
    single_transfer(spi, address <<< 1 &&& 0x7E, value)
  end

  defp read_register(spi, address) do
    single_transfer(spi, (address <<< 1 &&& 0x7E) ||| 0x80, 0x00)
  end

  defp single_transfer(spi, address, value) do
    GPIO.write(spi.ss, 0)
    <<_, resp>> = SPI.transfer(spi.pid, <<address, value>>)
    GPIO.write(spi.ss, 1)
    resp
  end
end
