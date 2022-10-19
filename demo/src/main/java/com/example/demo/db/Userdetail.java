package com.example.demo.db;

import java.io.Serializable;
import javax.persistence.*;
import java.util.Date;


/**
 * The persistent class for the userdetail database table.
 * 
 */
@Entity
public class Userdetail implements Serializable {
	private static final long serialVersionUID = 1L;

	@Id
	@Column
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;

	private String clientID;

	@Temporal(TemporalType.TIMESTAMP)
	private Date creationDate;

	private String deviceID;

	private String emailID;

	@Temporal(TemporalType.TIMESTAMP)
	private Date modificationDate;

	private int phoneNO;

	@Lob
	private byte[] photo;

	@Lob
	private byte[] voiceData;

	public Userdetail() {
	}

	public int getId() {
		return this.id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getClientID() {
		return this.clientID;
	}

	public void setClientID(String clientID) {
		this.clientID = clientID;
	}

	public Date getCreationDate() {
		return this.creationDate;
	}

	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	public String getDeviceID() {
		return this.deviceID;
	}

	public void setDeviceID(String deviceID) {
		this.deviceID = deviceID;
	}

	public String getEmailID() {
		return this.emailID;
	}

	public void setEmailID(String emailID) {
		this.emailID = emailID;
	}

	public Date getModificationDate() {
		return this.modificationDate;
	}

	public void setModificationDate(Date modificationDate) {
		this.modificationDate = modificationDate;
	}

	public int getPhoneNO() {
		return this.phoneNO;
	}

	public void setPhoneNO(int phoneNO) {
		this.phoneNO = phoneNO;
	}

	public byte[] getPhoto() {
		return this.photo;
	}

	public void setPhoto(byte[] photo) {
		this.photo = photo;
	}

	public byte[] getVoiceData() {
		return this.voiceData;
	}

	public void setVoiceData(byte[] voiceData) {
		this.voiceData = voiceData;
	}

}