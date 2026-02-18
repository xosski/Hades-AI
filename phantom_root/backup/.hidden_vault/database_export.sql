# CANARY:PHANTOM_64af90a12c782acd
-- MySQL dump 10.13  Distrib 5.7.32
-- Server version 5.7.32-log

DROP TABLE IF EXISTS `admin_users`;
CREATE TABLE `admin_users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `api_key` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`)
);

INSERT INTO `admin_users` VALUES 
(1,'admin','$2y$10$fakehashvaluehere123456','ak_live_abc123'),
(2,'superuser','$2y$10$anotherfakehash78901','ak_live_xyz789');

-- Dump completed
