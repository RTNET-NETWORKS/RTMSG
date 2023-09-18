-- phpMyAdmin SQL Dump
-- version 5.2.1deb1
-- https://www.phpmyadmin.net/
--
-- Hôte : localhost:3306
-- Généré le : lun. 18 sep. 2023 à 19:47
-- Version du serveur : 10.11.3-MariaDB-1
-- Version de PHP : 8.2.7

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de données : `rtmsg`
--

-- --------------------------------------------------------

--
-- Structure de la table `admin`
--

CREATE TABLE `admin` (
  `id` int(16) NOT NULL,
  `user` varchar(32) NOT NULL COMMENT 'Nom de l''utilisateur',
  `level` enum('1','2','3','4') NOT NULL COMMENT 'Niveau de permissions',
  `heure` datetime NOT NULL DEFAULT current_timestamp() COMMENT 'Heure de promotion',
  `system` tinyint(1) DEFAULT 0 COMMENT 'Le compte est-il système ?'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Liste des administrateurs';

-- --------------------------------------------------------

--
-- Structure de la table `invitation`
--

CREATE TABLE `invitation` (
  `id` int(16) NOT NULL COMMENT 'Identifiant de l''invitation',
  `user` varchar(32) NOT NULL COMMENT 'Utilisateur à l''origine de l''invitation',
  `target` varchar(32) NOT NULL COMMENT 'Nom d''utilisateur de la personne invitée',
  `code` varchar(32) NOT NULL COMMENT 'Code d''invitation'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Liste des invitations pour ajouter un nouvel utilisateur';

-- --------------------------------------------------------

--
-- Structure de la table `messages`
--

CREATE TABLE `messages` (
  `id` int(32) NOT NULL COMMENT 'Identifiant du message',
  `source` varchar(32) NOT NULL COMMENT 'Utilisateur à l''origine du message',
  `target` varchar(32) NOT NULL COMMENT 'Destinataire du message',
  `message` text DEFAULT NULL COMMENT 'Corps du message (chiffré)',
  `message_read` tinyint(1) NOT NULL DEFAULT 0 COMMENT 'Etat de lecture du message'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Table contenant les messages chiffrés';

-- --------------------------------------------------------

--
-- Structure de la table `operation`
--

CREATE TABLE `operation` (
  `id` int(16) NOT NULL COMMENT 'Identifiant de l''opération',
  `user` varchar(32) NOT NULL COMMENT 'Utilisateur ayant produit l''opération',
  `type` enum('authentication','change_key','communication','failed_authentication','send_message','register_user','deconnection','forbidden','grant','bad_target','drop_user','rtkey_send_passwd','rtkey_check_passwd','bad_invitation','invitation','registration','delete_message','rtkey_bad_passwd') NOT NULL COMMENT 'Nature de l''opération',
  `target` varchar(32) DEFAULT NULL COMMENT 'Éventuel destinataire, dans le cas d''une communication',
  `heure` datetime NOT NULL DEFAULT current_timestamp() COMMENT 'Heure de l''opération'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Liste des opérations';

-- --------------------------------------------------------

--
-- Structure de la table `passwd`
--

CREATE TABLE `passwd` (
  `id` int(16) NOT NULL COMMENT 'Identifiant du mot de passe stocké',
  `user` varchar(32) NOT NULL COMMENT 'Utilisateur lié au mot de passe',
  `date` datetime NOT NULL DEFAULT current_timestamp() COMMENT 'Heure d''ajout du mot de passe',
  `password` text NOT NULL COMMENT 'Mot de passe chiffré',
  `name` varchar(64) NOT NULL COMMENT 'Nom associé au mot de passe'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Table des mots de passes de RTKEY';

-- --------------------------------------------------------

--
-- Structure de la table `users`
--

CREATE TABLE `users` (
  `id` int(16) NOT NULL COMMENT 'Identifiant unique d''un utilisateur',
  `user` varchar(32) NOT NULL COMMENT 'Nom de l''utilisateur',
  `address` varchar(64) DEFAULT NULL COMMENT 'Adresse utilisée dans la trame du protocole (à mettre en place)',
  `clef` text DEFAULT NULL COMMENT 'Clef publique associée à l''utilisateur'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Liste des utilisateurs et des informations de connexion';

--
-- Index pour les tables déchargées
--

--
-- Index pour la table `admin`
--
ALTER TABLE `admin`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user` (`user`);

--
-- Index pour la table `invitation`
--
ALTER TABLE `invitation`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_invitation` (`target`);

--
-- Index pour la table `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `source` (`source`),
  ADD KEY `target` (`target`);

--
-- Index pour la table `operation`
--
ALTER TABLE `operation`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user` (`user`);

--
-- Index pour la table `passwd`
--
ALTER TABLE `passwd`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_utilisateur_libelle` (`user`,`name`);

--
-- Index pour la table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `user` (`user`),
  ADD KEY `address` (`address`);

--
-- AUTO_INCREMENT pour les tables déchargées
--

--
-- AUTO_INCREMENT pour la table `admin`
--
ALTER TABLE `admin`
  MODIFY `id` int(16) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `invitation`
--
ALTER TABLE `invitation`
  MODIFY `id` int(16) NOT NULL AUTO_INCREMENT COMMENT 'Identifiant de l''invitation';

--
-- AUTO_INCREMENT pour la table `messages`
--
ALTER TABLE `messages`
  MODIFY `id` int(32) NOT NULL AUTO_INCREMENT COMMENT 'Identifiant du message';

--
-- AUTO_INCREMENT pour la table `operation`
--
ALTER TABLE `operation`
  MODIFY `id` int(16) NOT NULL AUTO_INCREMENT COMMENT 'Identifiant de l''opération';

--
-- AUTO_INCREMENT pour la table `passwd`
--
ALTER TABLE `passwd`
  MODIFY `id` int(16) NOT NULL AUTO_INCREMENT COMMENT 'Identifiant du mot de passe stocké';

--
-- AUTO_INCREMENT pour la table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(16) NOT NULL AUTO_INCREMENT COMMENT 'Identifiant unique d''un utilisateur';

--
-- Contraintes pour les tables déchargées
--

--
-- Contraintes pour la table `admin`
--
ALTER TABLE `admin`
  ADD CONSTRAINT `Utilisateur` FOREIGN KEY (`user`) REFERENCES `users` (`user`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Contraintes pour la table `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `source` FOREIGN KEY (`source`) REFERENCES `users` (`user`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `target` FOREIGN KEY (`target`) REFERENCES `users` (`user`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Contraintes pour la table `operation`
--
ALTER TABLE `operation`
  ADD CONSTRAINT `user` FOREIGN KEY (`user`) REFERENCES `users` (`user`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Contraintes pour la table `passwd`
--
ALTER TABLE `passwd`
  ADD CONSTRAINT `user_relation` FOREIGN KEY (`user`) REFERENCES `users` (`user`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
