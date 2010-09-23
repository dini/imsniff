--
-- База данных: `security`
--

-- --------------------------------------------------------

--
-- Структура таблицы `sniff`
--

CREATE TABLE IF NOT EXISTS `sniff` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `ip` varchar(20) DEFAULT NULL,
  `proto` int(11) NOT NULL,
  `from_handle` varchar(255) DEFAULT NULL,
  `to_handle` varchar(255) DEFAULT NULL,
  `msg` text,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 ;
