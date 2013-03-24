# == Schema Information
#
# Table name: users
#
#  id         :integer          not null, primary key
#  name       :string(255)
#  email      :string(255)
#  created_at :datetime         not null
#  updated_at :datetime         not null
#

# SHA2 шифрование
require 'digest'

class User < ActiveRecord::Base
	# Виртуальный атрибут, не создающий записи в БД
	attr_accessor :password
	
	# Обычные атрибуты, которым соответствуют записи в БД
	attr_accessible :name, :email, :password, :password_confirmation
	
	email_regex = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
	
	validates :name,  		:presence 		=> true,							# Валидация наличия атрибута name
							:length   		=> { :maximum => 50 }				# Валидация длины атрибута name
	validates :email, 		:presence 		=> true,							# Валидация наличия атрибута email
							:format   		=> { :with => email_regex },		# Валидация формата атрибута email с помощью регулярного выражения
							:uniqueness 	=> { :case_sensitive => false }		# Валидация значения атрибута email на уникальность (без учета регистра символов)
	validates :password, 	:presence 		=> true,							# Валидация наличия атрибута password
							:confirmation 	=> true,							# Валидация равенства атрибутов password и confirmation
							:length 		=> { :within => 6..40 }				# Валидация длины атрибута password
						 
	# до сохранения атрибута encrypt_password вызывается метод encrypt_password (шифрования атрибута) 
	before_save :encrypt_password
	
	# валидация равен ли введенный в форме пароль - паролю из БД
	def has_password?(submitted_password)
		encrypted_password == encrypt(submitted_password)
	end
	
	# метод, определяющий аутентифицирован ли пользователь, в случае успеха вовзвращется объект user, соответствующий данному пользователю
	def self.authenticate(email, submitted_password)
		user = find_by_email(email)
		return nil if user.nil?
		return user if user.has_password?(submitted_password)
	end
	
	private
	
		def encrypt_password
			self.salt = make_salt if new_record?				# new_record? - возвращает true если объект еще не сохранен в БД
			self.encrypted_password = encrypt(self.password)
		end
				
		def encrypt(string)
			secure_hash("#{self.salt}--#{string}")
		end
		
		def make_salt
			secure_hash("#{Time.now.utc}--#{password}")
		end
		
		def secure_hash(string)
			Digest::SHA2.hexdigest(string)
		end		
end